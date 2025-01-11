package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

func main() {
	verbose := flag.Bool("v", false, "verbose output (distinguishes between STDOUT and STDERR)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-v] [command]\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nRun command quietly unless it fails (exit code not 0)\n")
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	os.Exit(run(*verbose))
}

func run(verbose bool) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigChan)

	go func() {
		<-sigChan
		cancel()
	}()

	cmd := exec.CommandContext(ctx, flag.Arg(0), flag.Args()[1:]...)

	var stdout, stderr bytes.Buffer
	stdout.Grow(4096)
	stderr.Grow(4096)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = os.Stdin

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}

	if err := cmd.Start(); err != nil {
		return 1
	}

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
		showOutput(&stdout, &stderr, exitCode, verbose)
	}
	return exitCode
}

func showOutput(stdout, stderr *bytes.Buffer, retval int, verbose bool) {
	stdoutContent := stdout.Bytes()
	stderrContent := stderr.Bytes()

	if len(stdoutContent) > 0 {
		if verbose {
			fmt.Print("STDOUT:\n")
		}
		os.Stdout.Write(stdoutContent)
	}

	if len(stderrContent) > 0 {
		if verbose {
			if len(stdoutContent) > 0 {
				fmt.Print("\n")
			}
			fmt.Print("STDERR:\n")
		}
		os.Stderr.Write(stderrContent)
	}

	if verbose {
		fmt.Printf("\nRETVAL: %d\n", retval)
	}
}
