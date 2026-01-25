package main

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

const maxInputRunes = 131072 // ~1MB output (8 bytes/rune worst case)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: htmlentify [text]")
		fmt.Fprintln(os.Stderr, "Convert text to HTML entities")
		os.Exit(1)
	}

	input := strings.Join(os.Args[1:], " ")
	runeCount := utf8.RuneCountInString(input)

	if runeCount > maxInputRunes {
		fmt.Fprintln(os.Stderr, "Error: input exceeds maximum length")
		os.Exit(1)
	}

	var hex, dec strings.Builder
	hex.Grow(runeCount * 8)
	dec.Grow(runeCount * 7)

	for _, r := range input {
		fmt.Fprintf(&hex, "&#x%X;", r)
		fmt.Fprintf(&dec, "&#%d;", r)
	}

	fmt.Println("hex:", hex.String())
	fmt.Println("dec:", dec.String())
}
