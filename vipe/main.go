package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s \nAllows editing piped data in your $EDITOR\n", os.Args[0])
	}

	help := flag.Bool("help", false, "show help")
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if !checkStdinPipe() {
		fmt.Fprintf(os.Stderr, "Error: no data piped to stdin\n")
		os.Exit(1)
	}

	tmpFile, err := createSecureTempFile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	tmpName := tmpFile.Name()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sigChan
		secureShred(tmpName)
		os.Exit(1)
	}()
	defer secureShred(tmpName)

	if err := copyWithProgress(tmpFile, os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "Error copying stdin: %v\n", err)
		os.Exit(1)
	}
	tmpFile.Close()

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening TTY: %v\n", err)
		os.Exit(1)
	}
	defer tty.Close()

	editor := getEditor()
	cmdParts := strings.Fields(editor)
	cmd := exec.Command(cmdParts[0], append(cmdParts[1:], tmpName)...)
	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.Stderr = tty

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Editor error: %v\n", err)
		os.Exit(1)
	}

	edited, err := os.Open(tmpName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading edited file: %v\n", err)
		os.Exit(1)
	}
	defer edited.Close()

	if err := copyWithProgress(os.Stdout, edited); err != nil {
		fmt.Fprintf(os.Stderr, "Error copying to stdout: %v\n", err)
		os.Exit(1)
	}
}

func checkStdinPipe() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func copyWithProgress(dst io.Writer, src io.Reader) error {
	buf := make([]byte, 32*1024)
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

func secureRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func createSecureTempFile() (*os.File, error) {
	randStr, err := secureRandomString(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random string: %w", err)
	}

	tmpDir := os.TempDir()
	filename := filepath.Join(tmpDir, fmt.Sprintf("vipe-%s.tmp", randStr))

	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	return file, nil
}

func getEditor() string {
	for _, env := range []string{"EDITOR", "VISUAL"} {
		if editor := os.Getenv(env); editor != "" {
			return editor
		}
	}
	if _, err := os.Stat("/usr/bin/editor"); err == nil {
		return "/usr/bin/editor"
	}
	return "vi"
}

func secureShred(filename string) error {
	zeros := make([]byte, 32*1024)
	file, err := os.OpenFile(filename, os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	for i := 0; i < 3; i++ {
		if _, err := file.Seek(0, 0); err != nil {
			return err
		}
		remaining := info.Size()
		for remaining > 0 {
			writeSize := int64(len(zeros))
			if remaining < writeSize {
				writeSize = remaining
			}
			if _, err := file.Write(zeros[:writeSize]); err != nil {
				return err
			}
			remaining -= writeSize
		}
		if err := file.Sync(); err != nil {
			return err
		}
	}
	return os.Remove(filename)
}
