package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
)

const bufferSize = 1024 * 1024 // 1MB for better performance with large files

var helpFlag = flag.Bool("help", false, "display usage information")

func usage() {
	if *helpFlag {
		fmt.Fprintf(os.Stderr, "Usage: sponge [file]\nSoak up standard input and write to a file\n")
		os.Exit(0)
	}
}

func cleanup(tmpfile string) {
	if tmpfile != "" {
		err := os.Remove(tmpfile)
		if err != nil {
			os.Exit(1)
		}
	}
}

func setupSecureTempFile() (*os.File, string, error) {
	oldMask := syscall.Umask(0077)
	defer syscall.Umask(oldMask)

	tmpdir := os.Getenv("TMPDIR")
	if tmpdir == "" {
		tmpdir = "/tmp"
	}

	// Validate tmpdir is absolute
	if !filepath.IsAbs(tmpdir) {
		return nil, "", fmt.Errorf("temporary directory path must be absolute")
	}

	if err := os.MkdirAll(tmpdir, 0700); err != nil {
		return nil, "", fmt.Errorf("failed to create temp directory: %v", err)
	}

	tmpfile, err := os.CreateTemp(tmpdir, "sponge-*.tmp")
	if err != nil {
		return nil, "", fmt.Errorf("failed to create temp file: %v", err)
	}

	// Immediately chmod to secure permissions
	if err := tmpfile.Chmod(0600); err != nil {
		tmpfile.Close()
		os.Remove(tmpfile.Name())
		return nil, "", fmt.Errorf("failed to set temp file permissions: %v", err)
	}

	return tmpfile, tmpfile.Name(), nil
}

func handleSignals(tmpfile string, done chan<- struct{}) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGHUP,
		syscall.SIGQUIT,
		syscall.SIGABRT,
		syscall.SIGPIPE)

	go func() {
		<-sigChan
		signal.Reset()
		cleanup(tmpfile)
		close(done)
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

	flag.Parse()

	if *helpFlag {
		usage()
	}

	var outfile string
	if flag.NArg() > 0 {
		var err error
		outfile, err = filepath.Abs(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving output path: %v\n", err)
			os.Exit(1)
		}

		// Validate output directory exists
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
	defer cleanup(tmpname)

	done := make(chan struct{})
	handleSignals(tmpname, done)

	if err := copyWithBuffer(tmpfile, os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
		os.Exit(1)
	}

	if outfile == "" {
		if _, err := tmpfile.Seek(0, io.SeekStart); err != nil {
			fmt.Fprintf(os.Stderr, "Error seeking temp file: %v\n", err)
			os.Exit(1)
		}
		if err := copyWithBuffer(os.Stdout, tmpfile); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to stdout: %v\n", err)
			os.Exit(1)
		}
		return
	}

	var mode os.FileMode = 0600
	if info, err := os.Stat(outfile); err == nil {
		mode = info.Mode() & 0777
	}

	if err := tmpfile.Sync(); err != nil {
		fmt.Fprintf(os.Stderr, "Error syncing temporary file: %v\n", err)
		os.Exit(1)
	}

	if err := tmpfile.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Error closing temporary file: %v\n", err)
		os.Exit(1)
	}

	// Try atomic rename
	if err := os.Rename(tmpname, outfile); err != nil {
		// Fallback to copy if rename fails
		src, err := os.Open(tmpname)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening temp file: %v\n", err)
			os.Exit(1)
		}
		defer src.Close()

		// Create with restrictive permissions first
		dst, err := os.OpenFile(outfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
			os.Exit(1)
		}
		defer dst.Close()

		if err := copyWithBuffer(dst, src); err != nil {
			fmt.Fprintf(os.Stderr, "Error copying to output file: %v\n", err)
			os.Exit(1)
		}

		if err := dst.Chmod(mode); err != nil {
			fmt.Fprintf(os.Stderr, "Error setting output file permissions: %v\n", err)
			os.Exit(1)
		}

		if err := dst.Sync(); err != nil {
			fmt.Fprintf(os.Stderr, "Error syncing output file: %v\n", err)
			os.Exit(1)
		}
	}
}
