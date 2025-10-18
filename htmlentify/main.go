package main

import (
	"fmt"
	"os"
	"strings"
)

const maxInputLength = 1048576 // 1MB

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: htmlentify [text]")
		fmt.Fprintln(os.Stderr, "Convert text to HTML entities")
		os.Exit(1)
	}

	input := strings.Join(os.Args[1:], " ")

	if len(input) > maxInputLength {
		fmt.Fprintln(os.Stderr, "Error: input exceeds maximum length")
		os.Exit(1)
	}

	var hex, dec strings.Builder
	hex.Grow(len(input) * 8)
	dec.Grow(len(input) * 7)

	for _, r := range input {
		fmt.Fprintf(&hex, "&#x%X;", r)
		fmt.Fprintf(&dec, "&#%d;", r)
	}

	fmt.Println("hex:", hex.String())
	fmt.Println("dec:", dec.String())
}
