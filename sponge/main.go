package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
)

const bufferSize = 1024 * 1024

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: sponge [file]\nSoak up standard input and write to a file\n")
}

func cleanup(tmpfile string) {
	if tmpfile != "" {
		os.Remove(tmpfile)
	}
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

	// Generate cryptographically random string for filename (16 characters)
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, "", fmt.Errorf("Failed to generate random filename: %v", err)
	}

	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}

	tmpname := filepath.Join(tmpdir, fmt.Sprintf("sponge-%s.tmp", string(b)))

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
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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
		return
	}

	src, openErr := os.Open(tmpname)
	if openErr != nil {
		cleanup(tmpname)
		fmt.Fprintf(os.Stderr, "Error opening temp file: %v\n", openErr)
		os.Exit(1)
	}
	defer src.Close()

	dst, openErr := os.OpenFile(outfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if openErr != nil {
		cleanup(tmpname)
		fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", openErr)
		os.Exit(1)
	}
	defer dst.Close()

	if err := copyWithBuffer(dst, src); err != nil {
		cleanup(tmpname)
		fmt.Fprintf(os.Stderr, "Error copying to output file: %v\n", err)
		os.Exit(1)
	}

	if err := dst.Sync(); err != nil {
		cleanup(tmpname)
		fmt.Fprintf(os.Stderr, "Error syncing output file: %v\n", err)
		os.Exit(1)
	}

	cleanup(tmpname)
}
