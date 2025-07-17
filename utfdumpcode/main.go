package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func printUsage(toolName string) {
	fmt.Fprintf(os.Stderr, "Usage: %s [file]\nDump Unicode code points\n", toolName)
}

func processInput(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)

	// Increase buffer size for extremely large files
	const maxCapacity = 4 * 1024 * 1024 // 4MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		line := scanner.Text()
		for _, char := range line {
			// Format with %06X for characters beyond BMP (up to 0x10FFFF)
			if char > 0xFFFF {
				fmt.Printf("U+%06X %s\n", char, string(char))
			} else {
				fmt.Printf("U+%04X %s\n", char, string(char))
			}
		}
	}
	return scanner.Err()
}

func main() {
	toolName := filepath.Base(os.Args[0])

	if len(os.Args) > 1 {
		arg := os.Args[1]

		// Check if it's a flag (and make sure it's not a valid file)
		if strings.HasPrefix(arg, "-") {
			// Check if the file actually exists despite starting with "-"
			_, err := os.Stat(arg)
			if err != nil && os.IsNotExist(err) {
				// It's not a file, treat as a flag
				if arg != "-v" {
					fmt.Fprintf(os.Stderr, "Flag provided but not defined: %s\n", arg)
					printUsage(toolName)
					os.Exit(1)
				} else {
					printUsage(toolName)
					return
				}
			}
		}

		file, err := os.Open(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		if err := processInput(file); err != nil {
			fmt.Fprintf(os.Stderr, "Error processing input: %v\n", err)
			os.Exit(1)
		}
	} else if !hasStdin() {
		printUsage(toolName)
	} else {
		if err := processInput(os.Stdin); err != nil {
			fmt.Fprintf(os.Stderr, "Error processing input: %v\n", err)
			os.Exit(1)
		}
	}
}

// hasStdin checks if there is data available on stdin
func hasStdin() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) == 0
}
