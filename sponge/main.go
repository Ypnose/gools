package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

const bufferSize = 1024 * 1024

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: sponge [file]\nSoak up standard input and write to a file\n")
}

func secureDelete(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err == nil {
		stat, err := f.Stat()
		if err == nil {
			f.Seek(0, 0)
			zeros := make([]byte, 4096)
			remaining := stat.Size()
			for remaining > 0 {
				writeSize := int64(len(zeros))
				if remaining < writeSize {
					writeSize = remaining
				}
				written := 0
				for written < int(writeSize) {
					n, err := f.Write(zeros[written:writeSize])
					if err != nil || n <= 0 {
						break
					}
					written += n
				}
				if written < int(writeSize) {
					break
				}
				remaining -= writeSize
			}
			f.Sync()
		}
		f.Close()
	}
	os.Remove(path)
}

func cleanup(tmpfile string) {
	if tmpfile != "" {
		secureDelete(tmpfile)
	}
}

func generateRandomName() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("Failed to generate random filename: %v", err)
	}
	return hex.EncodeToString(bytes), nil
}

func setupSecureTempFile() (*os.File, string, error) {
	oldMask := syscall.Umask(0077)
	defer syscall.Umask(oldMask)

	tmpdir := os.Getenv("TMPDIR")
	if tmpdir == "" {
		tmpdir = "/tmp"
	}

	if !filepath.IsAbs(tmpdir) {
		return nil, "", fmt.Errorf("Temporary directory path must be absolute")
	}

	if err := os.MkdirAll(tmpdir, 0700); err != nil {
		return nil, "", fmt.Errorf("Failed to create temp directory: %v", err)
	}

	randName, err := generateRandomName()
	if err != nil {
		return nil, "", err
	}

	tmpname := filepath.Join(tmpdir, fmt.Sprintf("sponge-%s.tmp", randName))

	tmpfile, err := os.OpenFile(tmpname, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, "", fmt.Errorf("Failed to create temp file: %v", err)
	}

	return tmpfile, tmpname, nil
}

func handleSignals(tmpfile string) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGHUP)

	go func() {
		<-sigChan
		signal.Reset()
		cleanup(tmpfile)
		os.Exit(1)
	}()
}

func copyWithBuffer(dst *os.File, src *os.File) error {
	buf := make([]byte, bufferSize)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			written := 0
			for written < n {
				m, werr := dst.Write(buf[written:n])
				if werr != nil {
					return werr
				}
				if m <= 0 {
					return fmt.Errorf("write returned %d", m)
				}
				written += m
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	flag.Usage = func() {
		if len(os.Args) > 1 && os.Args[1] == "-help" {
			usage()
			os.Exit(0)
		}
		if len(os.Args) > 1 {
			fmt.Fprintf(os.Stderr, "Flag provided but not defined: %s\n", os.Args[1])
		}
		usage()
		os.Exit(1)
	}
	flag.Parse()

	var outfile string
	if flag.NArg() > 0 {
		var err error
		outfile, err = filepath.Abs(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving output path: %v\n", err)
			os.Exit(1)
		}

		outDir := filepath.Dir(outfile)
		if _, err := os.Stat(outDir); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Output directory does not exist\n")
			os.Exit(1)
		}
	}

	tmpfile, tmpname, err := setupSecureTempFile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	handleSignals(tmpname)

	if err := copyWithBuffer(tmpfile, os.Stdin); err != nil {
		tmpfile.Close()
		cleanup(tmpname)
		fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
		os.Exit(1)
	}

	if outfile == "" {
		if _, err := tmpfile.Seek(0, io.SeekStart); err != nil {
			tmpfile.Close()
			cleanup(tmpname)
			fmt.Fprintf(os.Stderr, "Error seeking temp file: %v\n", err)
			os.Exit(1)
		}
		if err := copyWithBuffer(os.Stdout, tmpfile); err != nil {
			tmpfile.Close()
			cleanup(tmpname)
			fmt.Fprintf(os.Stderr, "Error writing to stdout: %v\n", err)
			os.Exit(1)
		}
		tmpfile.Close()
		cleanup(tmpname)
		return
	}

	var mode os.FileMode = 0600
	if info, err := os.Stat(outfile); err == nil {
		mode = info.Mode() & 0777
	}

	if err := tmpfile.Sync(); err != nil {
		tmpfile.Close()
		cleanup(tmpname)
		fmt.Fprintf(os.Stderr, "Error syncing temporary file: %v\n", err)
		os.Exit(1)
	}

	if err := tmpfile.Close(); err != nil {
		cleanup(tmpname)
		fmt.Fprintf(os.Stderr, "Error closing temporary file: %v\n", err)
		os.Exit(1)
	}

	if err := os.Rename(tmpname, outfile); err == nil {
		if mode != 0600 {
			os.Chmod(outfile, mode)
		}
		return
	}

	outDir := filepath.Dir(outfile)
	randName, err := generateRandomName()
	if err != nil {
		cleanup(tmpname)
		fmt.Fprintf(os.Stderr, "Error generating random name: %v\n", err)
		os.Exit(1)
	}
	tmpOutName := filepath.Join(outDir, fmt.Sprintf(".sponge-%s.tmp", randName))

	src, err := os.Open(tmpname)
	if err != nil {
		cleanup(tmpname)
		fmt.Fprintf(os.Stderr, "Error opening temp file: %v\n", err)
		os.Exit(1)
	}

	dst, err := os.OpenFile(tmpOutName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		src.Close()
		cleanup(tmpname)
		fmt.Fprintf(os.Stderr, "Error creating output temp file: %v\n", err)
		os.Exit(1)
	}

	if err := copyWithBuffer(dst, src); err != nil {
		dst.Close()
		src.Close()
		os.Remove(tmpOutName)
		cleanup(tmpname)
		fmt.Fprintf(os.Stderr, "Error copying to output: %v\n", err)
		os.Exit(1)
	}

	if err := dst.Sync(); err != nil {
		dst.Close()
		src.Close()
		os.Remove(tmpOutName)
		cleanup(tmpname)
		fmt.Fprintf(os.Stderr, "Error syncing output: %v\n", err)
		os.Exit(1)
	}

	dst.Close()
	src.Close()

	if err := os.Rename(tmpOutName, outfile); err != nil {
		os.Remove(tmpOutName)
		cleanup(tmpname)
		fmt.Fprintf(os.Stderr, "Error renaming to final output: %v\n", err)
		os.Exit(1)
	}

	cleanup(tmpname)
}
