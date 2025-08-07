package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

const usage = `Usage: sleep [seconds]
Do I really need to describe this tool ?`

func main() {
	args := os.Args[1:]

	if len(args) == 0 || args[0] == "-h" {
		fmt.Println(usage)
		os.Exit(0)
	}

	if len(args) > 1 {
		fmt.Println(usage)
		os.Exit(1)
	}

	secondsStr := args[0]
	seconds, err := strconv.Atoi(secondsStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid number '%s'\n", secondsStr)
		os.Exit(1)
	}

	// Validate range (prevent negative values and extremely large values)
	if seconds < 0 {
		fmt.Fprintf(os.Stderr, "Negative sleep time\n")
		os.Exit(1)
	}

	if seconds > 2147483647 {
		fmt.Fprintf(os.Stderr, "Sleep time too large\n")
		os.Exit(1)
	}

	time.Sleep(time.Duration(seconds) * time.Second)
}
