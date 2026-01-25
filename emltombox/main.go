package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultBufSize    = 64 * 1024
	maxScannerLineLen = 1024 * 1024
)

type messageInfo struct {
	from string
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [-output output.mbox] file1.eml [file2.eml ...]\n",
			filepath.Base(os.Args[0]))
	}

	outputFile := flag.String("output", "output.mbox", "Output MBOX file path")
	flag.Parse()

	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if err := validatePath(*outputFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	out, err := os.OpenFile(*outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	writer := bufio.NewWriterSize(out, defaultBufSize)
	infos := make([]messageInfo, 0, len(flag.Args()))
	successCount := 0

	for _, emlPath := range flag.Args() {
		info, err := convertEMLToMBOX(emlPath, writer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", emlPath, err)
			continue
		}
		infos = append(infos, info)
		successCount++
	}

	if err := writer.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to output file: %v\n", err)
		os.Exit(1)
	}

	if successCount == 0 {
		fmt.Fprintf(os.Stderr, "No files were successfully converted\n")
		os.Exit(1)
	}

	if err := verifyOrder(*outputFile, infos); err != nil {
		fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully converted and verified %d EML files in %s\n", successCount, *outputFile)
}

func validatePath(pathStr string) error {
	if strings.ContainsAny(pathStr, "\x00") {
		return fmt.Errorf("Invalid character in path")
	}

	dir := filepath.Dir(pathStr)
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return fmt.Errorf("Not a directory: %s", dir)
	}

	return nil
}

func convertEMLToMBOX(emlPath string, writer *bufio.Writer) (messageInfo, error) {
	info := messageInfo{}

	if strings.ContainsAny(emlPath, "\x00") {
		return info, fmt.Errorf("Invalid character in input path")
	}

	emlFile, err := os.Open(emlPath)
	if err != nil {
		return info, err
	}
	defer emlFile.Close()

	scanner := bufio.NewScanner(emlFile)
	buf := make([]byte, defaultBufSize)
	scanner.Buffer(buf, maxScannerLineLen)

	var from string
	var dateStr string
	var currentHeader string
	var currentValue string

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimRight(line, "\r")

		if line == "" {
			break
		}

		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if currentHeader != "" {
				currentValue += " " + strings.TrimSpace(line)
			}
			continue
		}

		// Save previous header (first occurrence only)
		if currentHeader == "from" && from == "" {
			from = currentValue
		} else if currentHeader == "date" && dateStr == "" {
			dateStr = currentValue
		}

		if idx := strings.Index(line, ":"); idx != -1 {
			currentHeader = strings.ToLower(strings.TrimSpace(line[:idx]))
			currentValue = strings.TrimSpace(line[idx+1:])
		}
	}

	if currentHeader == "from" && from == "" {
		from = currentValue
	} else if currentHeader == "date" && dateStr == "" {
		dateStr = currentValue
	}

	if err := scanner.Err(); err != nil {
		return info, err
	}

	fromAddr := "MAILER-DAEMON@localhost"
	if from != "" {
		if addr, err := mail.ParseAddress(from); err == nil {
			fromAddr = addr.Address
		} else {
			fromAddr = from
		}
	}
	info.from = fromAddr

	// Parse date or use current time as fallback
	date := time.Now().UTC()
	if dateStr != "" {
		if parsedDate, err := mail.ParseDate(dateStr); err == nil {
			date = parsedDate
		}
	}

	// Write MBOX From_ line
	if _, err := fmt.Fprintf(writer, "From %s %s\n", fromAddr, date.Format(time.ANSIC)); err != nil {
		return info, err
	}

	// Reset to start
	if _, err := emlFile.Seek(0, 0); err != nil {
		return info, err
	}

	// Full copy of EML content
	reader := bufio.NewReader(emlFile)
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			if line != "" {
				line = strings.TrimRight(line, "\r")
				if strings.HasPrefix(line, "From ") || strings.HasPrefix(line, ">From ") {
					line = ">" + line
				}
				if _, err := writer.WriteString(line + "\n"); err != nil {
					return info, err
				}
			}
			break
		}
		if err != nil {
			return info, err
		}

		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "From ") || strings.HasPrefix(line, ">From ") {
			line = ">" + line
		}
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return info, err
		}
	}

	// Message separator
	if _, err := writer.WriteString("\n"); err != nil {
		return info, err
	}

	return info, nil
}

func verifyOrder(mboxPath string, infos []messageInfo) error {
	file, err := os.Open(mboxPath)
	if err != nil {
		return err
	}
	defer file.Close()

	idx := 0
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		line = strings.TrimRight(line, "\r\n")

		// Unescaped From_ line
		if strings.HasPrefix(line, "From ") && !strings.HasPrefix(line, ">") {
			if idx >= len(infos) {
				return fmt.Errorf("More messages than expected")
			}
			parts := strings.SplitN(line, " ", 3)
			if len(parts) < 2 || parts[1] != infos[idx].from {
				return fmt.Errorf("Message mismatch at position %d", idx+1)
			}
			idx++
		}
	}

	if idx != len(infos) {
		return fmt.Errorf("Found %d messages but expected %d", idx, len(infos))
	}

	return nil
}
