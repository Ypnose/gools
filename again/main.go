package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	bufferSize     = 4096
	maxInputLength = 1024
	commandTimeout = 30 * time.Second
)

var (
	validInputRegex = regexp.MustCompile(`^[a-zA-Z0-9\.\-_:@\s]+$`)
	// Shell related dangerous patterns
	dangerousPatterns = []string{
		// Command chaining
		"&&", "||", ";", "|",
		// Redirections
		">", ">>", "<", "<<<", ">&",
		// Command substitution
		"`", "$(", "${",
		// Shell expansions
		"~", "*", "?", "[", "]",
		// Process manipulation
		"&", "%", "!",
		// Fork bombs
		":(){ :", "(){",
		// Environment variables
		"$", "€", "£", "¥",
	}

	// Forbidden shells and interpreters
	forbiddenShells = []string{
		// Basic shells
		"sh", "bash", "dash", "zsh", "csh", "tcsh",
		// All ksh variants
		"ksh", "mksh", "pdksh", "ksh88", "ksh93", "dtksh", "SKsh",
		// Other shells and interpreters
		"fish", "rc", "scsh", "es", "ion", "elvish", "oil", "osh",
		// Scripting languages that can act as shells
		"python", "perl", "ruby", "php", "node", "lua",
		// Remote shells
		"rsh", "ssh", "telnet",
	}

	// Shell metacharacters and syntax
	shellMetacharacters = "`()[]{}$\\!'\"#^&*<>?|;"
)

func getToolName() string {
	return filepath.Base(os.Args[0])
}

func displayUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [command]\n", getToolName())
	fmt.Fprintf(os.Stderr, "Repeatedly executes the specified command\n")
	os.Exit(0)
}

type SecurityValidator struct {
	mu sync.RWMutex
}

func (sv *SecurityValidator) IsSecureCommand(cmd string) error {
	sv.mu.RLock()
	defer sv.mu.RUnlock()

	if len(cmd) == 0 || len(cmd) > maxInputLength {
		return fmt.Errorf("Invalid command length")
	}

	cmdLower := strings.ToLower(cmd)

	for _, pattern := range dangerousPatterns {
		if strings.Contains(cmdLower, strings.ToLower(pattern)) {
			return fmt.Errorf("Dangerous pattern detected: %s", pattern)
		}
	}

	for _, char := range shellMetacharacters {
		if strings.ContainsRune(cmd, char) {
			return fmt.Errorf("Shell metacharacter detected: %c", char)
		}
	}

	for _, shell := range forbiddenShells {
		shellPattern := regexp.MustCompile(fmt.Sprintf(`(?i)\b%s\b`, regexp.QuoteMeta(shell)))
		if shellPattern.MatchString(cmdLower) {
			return fmt.Errorf("Shell or interpreter detected: %s", shell)
		}
	}

	for _, r := range cmd {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return fmt.Errorf("Non-printable character detected")
		}
	}

	return nil
}

type SafetyChecker struct {
	selfPath string
	selfName string
	mu       sync.RWMutex
}

func NewSafetyChecker() (*SafetyChecker, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("Failed to get executable path: %v", err)
	}

	absPath, err := filepath.Abs(execPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to resolve absolute path: %v", err)
	}

	realPath, err := filepath.EvalSymlinks(absPath)
	if err == nil {
		absPath = realPath
	}

	return &SafetyChecker{
		selfPath: absPath,
		selfName: filepath.Base(absPath),
	}, nil
}

func (sc *SafetyChecker) IsSafeCommand(cmd string) error {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	if cmd == "" || cmd == "-help" {
		return fmt.Errorf("help")
	}

	// Check for shell commands first
	cmdLower := strings.ToLower(cmd)
	for _, shell := range forbiddenShells {
		shellPattern := regexp.MustCompile(fmt.Sprintf(`(?i)^.*%s.*$`, regexp.QuoteMeta(shell)))
		if shellPattern.MatchString(filepath.Base(cmdLower)) {
			return fmt.Errorf("Shell or interpreter not allowed: %s", shell)
		}
	}

	// Check for dangerous patterns in the base name only
	cmdBase := filepath.Base(cmd)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(strings.ToLower(cmdBase), strings.ToLower(pattern)) {
			return fmt.Errorf("Dangerous pattern detected: %s", pattern)
		}
	}

	// Handle both PATH and relative paths
	var cmdPath string
	var err error

	if strings.Contains(cmd, "/") || strings.Contains(cmd, "\\") {
		cmdPath, err = filepath.Abs(cmd)
		if err != nil {
			return fmt.Errorf("Failed to resolve path: %v", err)
		}
	} else {
		cmdPath, err = exec.LookPath(cmd)
		if err != nil {
			return fmt.Errorf("Command not found: %s", cmd)
		}
	}

	realPath, err := filepath.EvalSymlinks(cmdPath)
	if err == nil {
		cmdPath = realPath
	}

	if cmdPath == sc.selfPath {
		return fmt.Errorf("Cannot run %s recursively", getToolName())
	}

	info, err := os.Stat(cmdPath)
	if err != nil {
		return fmt.Errorf("Cannot access command: %v", err)
	}

	if info.IsDir() {
		return fmt.Errorf("Command path is a directory")
	}

	if info.Mode()&0111 == 0 {
		return fmt.Errorf("Command is not executable")
	}

	return nil
}

type InputValidator struct {
	securityValidator *SecurityValidator
	mutex            sync.RWMutex
}

func NewInputValidator() *InputValidator {
	return &InputValidator{
		securityValidator: &SecurityValidator{},
	}
}

func (v *InputValidator) Validate(input string) ([]string, error) {
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	input = strings.TrimSpace(input)

	if input == "" {
		return nil, nil
	}

	if len(input) > maxInputLength {
		return nil, fmt.Errorf("Input exceeds maximum length")
	}

	args := strings.Fields(input)
	for _, arg := range args {
		if strings.Contains(arg, "/") || strings.Contains(arg, "\\") {
			return nil, fmt.Errorf("Path separators not allowed in arguments")
		}

		if err := v.securityValidator.IsSecureCommand(arg); err != nil {
			return nil, fmt.Errorf("Invalid argument: %v", err)
		}
	}

	return args, nil
}

type CommandExecutor struct {
	baseCmd    string
	workingDir string
}

func NewCommandExecutor(baseCmd string) (*CommandExecutor, error) {
	startDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("Failed to get working directory: %v", err)
	}

	absPath, err := filepath.Abs(startDir)
	if err != nil {
		return nil, fmt.Errorf("Failed to resolve absolute path: %v", err)
	}

	return &CommandExecutor{
		baseCmd:    baseCmd,
		workingDir: absPath,
	}, nil
}

func (e *CommandExecutor) Execute(ctx context.Context, args []string) error {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, e.baseCmd, args...)

	cmd.Env = []string{}
	cmd.Dir = e.workingDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("Failed to verify working directory: %v", err)
	}

	absCurrentDir, err := filepath.Abs(currentDir)
	if err != nil {
		return fmt.Errorf("Failed to resolve current directory: %v", err)
	}

	if absCurrentDir != e.workingDir {
		return fmt.Errorf("Working directory has been changed, aborting")
	}

	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("Command timed out after %v", commandTimeout)
	}
	return err
}

func main() {
	if len(os.Args) != 2 {
		displayUsage()
	}

	safetyChecker, err := NewSafetyChecker()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize safety checker: %v\n", err)
		os.Exit(0)
	}

	if err := safetyChecker.IsSafeCommand(os.Args[1]); err != nil {
		if err.Error() == "help" {
			displayUsage()
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(0)
	}

	validator := NewInputValidator()
	executor, err := NewCommandExecutor(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize executor: %v\n", err)
		os.Exit(0)
	}

	reader := bufio.NewReaderSize(os.Stdin, bufferSize)
	ctx := context.Background()

	defer fmt.Println()

	for {
		fmt.Printf("[%s] > ", os.Args[1])

		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		args, err := validator.Validate(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid input: %v\n", err)
			continue
		}

		if args == nil {
			continue
		}

		if err := executor.Execute(ctx, args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
	}
}
