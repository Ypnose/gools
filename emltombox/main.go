package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
	"time"
)

const defaultBufSize = 4096 * 1024

type messageInfo struct {
	filename string
	from     string
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [-output output.mbox] file1.eml [file2.eml ...]\n",
			path.Base(os.Args[0]))
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

func validatePath(path string) error {
	if strings.ContainsAny(path, "\x00") {
		return fmt.Errorf("Invalid character in path")
	}

	dir := "."
	if idx := strings.LastIndex(path, "/"); idx != -1 {
		dir = path[:idx]
	}

	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("Directory does not exist: %s", dir)
		}
		return fmt.Errorf("Cannot access directory: %s", dir)
	}

	if !info.IsDir() {
		return fmt.Errorf("Not a directory: %s", dir)
	}

	return nil
}

func convertEMLToMBOX(emlPath string, writer *bufio.Writer) (messageInfo, error) {
	info := messageInfo{filename: emlPath}

	if strings.ContainsAny(emlPath, "\x00") {
		return info, fmt.Errorf("Invalid character in input path")
	}

	emlFile, err := os.OpenFile(emlPath, os.O_RDONLY, 0)
	if err != nil {
		return info, fmt.Errorf("Cannot open EML file: %v", err)
	}
	defer emlFile.Close()

	scanner := bufio.NewScanner(emlFile)
	buf := make([]byte, defaultBufSize)
	scanner.Buffer(buf, defaultBufSize)

	// First pass to get From and Date headers
	var from string
	var dateStr string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "From:") {
			from = strings.TrimSpace(line[5:])
		} else if strings.HasPrefix(line, "Date:") {
			dateStr = strings.TrimSpace(line[5:])
		}
		if from != "" && dateStr != "" {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return info, fmt.Errorf("Error reading EML file: %v", err)
	}

	if from == "" {
		from = "MAILER-DAEMON@localhost"
	} else if start := strings.LastIndex(from, "<"); start != -1 {
		if end := strings.LastIndex(from, ">"); end != -1 {
			from = from[start+1 : end]
		}
	}
	info.from = from

	// Parse date or use current time as fallback
	date := time.Now()
	if dateStr != "" {
		if parsedDate, err := time.Parse(time.RFC1123Z, dateStr); err == nil {
			date = parsedDate
		} else if parsedDate, err := time.Parse(time.RFC822Z, dateStr); err == nil {
			date = parsedDate
		} else if parsedDate, err := time.Parse("Mon, 2 Jan 2006 15:04:05 -0700", dateStr); err == nil {
			date = parsedDate
		}
	}

	// Write MBOX From_ line
	if _, err := fmt.Fprintf(writer, "From %s %s\n", from, date.Format("Mon Jan 2 15:04:05 2006")); err != nil {
		return info, fmt.Errorf("Cannot write From_ line: %v", err)
	}

	// Reset to start of file for full copy
	if _, err := emlFile.Seek(0, 0); err != nil {
		return info, fmt.Errorf("Cannot reset file position: %v", err)
	}

	// Full copy of EML content
	scanner = bufio.NewScanner(emlFile)
	scanner.Buffer(buf, defaultBufSize)

	for scanner.Scan() {
		line := scanner.Text()
		// Escape From_ lines in content
		if strings.HasPrefix(line, "From ") {
			line = ">" + line
		}
		if _, err := fmt.Fprintln(writer, line); err != nil {
			return info, fmt.Errorf("Cannot write line: %v", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return info, fmt.Errorf("Error reading EML content: %v", err)
	}

	// Add blank line between messages
	if _, err := fmt.Fprintln(writer); err != nil {
		return info, fmt.Errorf("Cannot write message separator: %v", err)
	}

	return info, nil
}

func verifyOrder(mboxPath string, infos []messageInfo) error {
	file, err := os.Open(mboxPath)
	if err != nil {
		return fmt.Errorf("Cannot open mbox for verification: %v", err)
	}
	defer file.Close()

	idx := 0
	scanner := bufio.NewScanner(file)
	buf := make([]byte, defaultBufSize)
	scanner.Buffer(buf, defaultBufSize)

	for scanner.Scan() && idx < len(infos) {
		line := scanner.Text()
		if strings.HasPrefix(line, "From ") {
			if !strings.Contains(line, infos[idx].from) {
				return fmt.Errorf("Message order mismatch at position %d", idx+1)
			}
			idx++
		}
	}

	if idx != len(infos) {
		return fmt.Errorf("Incorrect number of messages in output file")
	}

	return scanner.Err()
}
