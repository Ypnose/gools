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

const usageMsg = "Usage: vipe \nAllows editing piped data in your $EDITOR"

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

	tmpname := filepath.Join(tmpdir, fmt.Sprintf("vipe-%s.tmp", randName))

	tmpfile, err := os.OpenFile(tmpname, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, "", fmt.Errorf("Failed to create temp file: %v", err)
	}

	return tmpfile, tmpname, nil
}

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, usageMsg)
	}

	if len(os.Args) > 1 {
		arg := os.Args[1]
		if strings.HasPrefix(arg, "-") && arg != "-help" {
			fmt.Fprintf(os.Stderr, "Flag provided but not defined: %s\n%s\n", arg, usageMsg)
			os.Exit(1)
		}
	}

	flag.Parse()

	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(1)
	}

	if isTerminal(os.Stdin) {
		fmt.Fprintln(os.Stderr, "Error: no data piped to stdin")
		os.Exit(1)
	}

	tmpfile, tmpPath, err := setupSecureTempFile()
	if err != nil {
		fatal("Tempfile creation failed:", err)
	}

	cleanup := func() {
		if tmpPath != "" {
			secureDelete(tmpPath)
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		<-sigChan
		cleanup()
		os.Exit(1)
	}()

	defer cleanup()

	if _, err := io.Copy(tmpfile, os.Stdin); err != nil {
		fatal("stdin copy failed:", err)
	}
	if err := tmpfile.Sync(); err != nil {
		fatal("sync failed:", err)
	}
	tmpfile.Close()

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		if os.IsNotExist(err) {
			fatal("No TTY available:", err)
		}
		if os.IsPermission(err) {
			fatal("TTY access denied:", err)
		}
		fatal("TTY open failed:", err)
	}
	defer tty.Close()

	if _, err := tty.Stat(); err != nil {
		fatal("TTY stat failed:", err)
	}

	editor := getEditor()
	if editor == "" {
		fatal("No editor found:", fmt.Errorf("EDITOR/VISUAL not set and vi not available"))
	}

	editorParts := strings.Fields(editor)
	cmd := exec.Command(editorParts[0], append(editorParts[1:], tmpPath)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fatal("Editor failed:", err)
	}

	edited, err := os.OpenFile(tmpPath, os.O_RDONLY, 0600)
	if err != nil {
		fatal("Result open failed:", err)
	}
	defer edited.Close()

	if _, err := io.Copy(os.Stdout, edited); err != nil {
		fatal("Output failed:", err)
	}
}

func getEditor() string {
	if v := os.Getenv("VISUAL"); v != "" && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if e := os.Getenv("EDITOR"); e != "" && strings.TrimSpace(e) != "" {
		return strings.TrimSpace(e)
	}
	if _, err := os.Stat("/usr/bin/editor"); err == nil {
		return "/usr/bin/editor"
	}
	if _, err := os.Stat("/usr/bin/vi"); err == nil {
		return "vi"
	}
	return ""
}

func isTerminal(f *os.File) bool {
	if stat, err := f.Stat(); err != nil {
		return false
	} else {
		return (stat.Mode() & os.ModeCharDevice) != 0
	}
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

func fatal(msg string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	os.Exit(1)
}
