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
	"strings"
	"syscall"
)

const usageMsg = "Usage: vipe \nAllows editing piped data in your $EDITOR"

func generateRandomName() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		fatal("random generation failed:", err)
	}
	return hex.EncodeToString(bytes)
}

func main() {
	// Custom flag handling to match exact error messages
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, usageMsg)
	}

	if len(os.Args) > 1 {
		arg := os.Args[1]
		if strings.HasPrefix(arg, "-") && arg != "-help" {
			fmt.Fprintf(os.Stderr, "flag provided but not defined: %s\n%s\n", arg, usageMsg)
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

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	randName := generateRandomName()
	tmpfile, err := os.CreateTemp("", "vipe-"+randName+".*")
	if err != nil {
		fatal("tempfile creation failed:", err)
	}
	tmpPath := tmpfile.Name()

	cleanup := func() {
		secureDelete(tmpPath)
		os.Exit(1)
	}

	go func() {
		<-sigChan
		cleanup()
	}()

	defer cleanup()

	if err := tmpfile.Chmod(0600); err != nil {
		fatal("chmod failed:", err)
	}

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
			fatal("no TTY available:", err)
		}
		if os.IsPermission(err) {
			fatal("TTY access denied:", err)
		}
		fatal("TTY open failed:", err)
	}

	oldStdin, oldStdout := os.Stdin, os.Stdout
	defer func() {
		if err := tty.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close TTY: %v\n", err)
		}
		os.Stdin, os.Stdout = oldStdin, oldStdout
	}()

	if _, err := tty.Stat(); err != nil {
		fatal("TTY stat failed:", err)
	}

	os.Stdin, os.Stdout = tty, tty

	editor := getEditor()
	if editor == "" {
		fatal("no editor found:", fmt.Errorf("EDITOR/VISUAL not set and vi not available"))
	}

	editorParts := strings.Fields(editor)
	cmd := exec.Command(editorParts[0], append(editorParts[1:], tmpPath)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fatal("editor failed:", err)
	}

	edited, err := os.OpenFile(tmpPath, os.O_RDONLY, 0600)
	if err != nil {
		fatal("result open failed:", err)
	}
	defer edited.Close()

	if _, err := io.Copy(oldStdout, edited); err != nil {
		fatal("output failed:", err)
	}
}

func getEditor() string {
	if v := os.Getenv("VISUAL"); v != "" && v != " " {
		return strings.TrimSpace(v)
	}
	if e := os.Getenv("EDITOR"); e != "" && e != " " {
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
	if f, err := os.OpenFile(path, os.O_WRONLY, 0600); err == nil {
		defer f.Close()
		if stat, err := f.Stat(); err == nil {
			zeros := make([]byte, 4096)
			remaining := stat.Size()
			for remaining > 0 {
				writeSize := int64(len(zeros))
				if remaining < writeSize {
					writeSize = remaining
				}
				if _, err := f.Write(zeros[:writeSize]); err != nil {
					break
				}
				remaining -= writeSize
			}
			f.Sync()
		}
	}
	os.Remove(path)
}

func fatal(msg string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	os.Exit(1)
}
