package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	apiKey = "" // Source code API key (optional)
	defaultTimeout = 30 * time.Second
)

type SearchResult struct {
	OrganicResults []struct {
		Position      int    `json:"position"`
		Title         string `json:"title"`
		Link          string `json:"link"`
		RedirectLink  string `json:"redirect_link"`
		DisplayedLink string `json:"displayed_link"`
		Snippet       string `json:"snippet"`
		Source        string `json:"source"`
	} `json:"organic_results"`
}

type ResultEntry struct {
	Position int
	Line     string
}

func getAPIKey() string {
	if apiKey != "" {
		return apiKey
	}
	return os.Getenv("SERPAPI_KEY")
}

func sortResultsByPosition(results []ResultEntry) []ResultEntry {
	sort.Slice(results, func(i, j int) bool {
		return results[i].Position < results[j].Position
	})
	return results
}

func main() {
	binaryName := os.Args[0]

	fileFlag := flag.String("file", "", "Output file")
	queryFlag := flag.String("query", "", "Search query")
	helpFlag := flag.Bool("help", false, "Show help")

	flag.Parse()

	if *helpFlag {
		fmt.Printf("Usage: %s [-file FILE] [-query QUERY]\n", filepath.Base(binaryName))
		os.Exit(0)
	}

	if *queryFlag == "" || *fileFlag == "" {
		log.Println("Both -file and -query arguments are required")
		os.Exit(1)
	}

	syslogWriter, err := syslog.New(syslog.LOG_INFO, filepath.Base(binaryName))
	if err != nil {
		log.Println("Could not create syslog writer:", err)
		os.Exit(1)
	}
	defer syslogWriter.Close()

	apiKeyToUse := getAPIKey()
	if apiKeyToUse == "" {
		log.Println("No API key found")
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		InsecureSkipVerify: false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   defaultTimeout,
	}

	url := fmt.Sprintf("https://serpapi.com/search?api_key=%s&engine=google&q=%s&location=France&google_domain=google.com&gl=us&hl=en&safe=off&filter=0&num=200&device=mobile&cr=countryUS|countryFR|countryDE|countryRU|countryJP|countryKR|countryCN&lr=lang_en|lang_fr|lang_de|lang_ru|lang_ja|lang_ko|lang_zh-CN|lang_zh-TW",
		apiKeyToUse, *queryFlag)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		log.Println(fmt.Sprintf("Error creating request: %v", err))
		os.Exit(1)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Println(fmt.Sprintf("Error making request: %v", err))
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(fmt.Sprintf("Error reading response: %v", err))
		os.Exit(1)
	}

	var searchResult SearchResult
	err = json.Unmarshal(body, &searchResult)
	if err != nil {
		log.Println(fmt.Sprintf("Error parsing JSON: %v", err))
		os.Exit(1)
	}

	currentResultLinks := make(map[string]int)
	for _, result := range searchResult.OrganicResults {
		currentResultLinks[result.Link] = result.Position
	}

	tempFile := *fileFlag + ".tmp"
	outputFile, err := os.Create(tempFile)
	if err != nil {
		log.Println(fmt.Sprintf("Error creating temp file: %v", err))
		os.Exit(1)
	}
	defer outputFile.Close()

	writer := bufio.NewWriter(outputFile)
	newResultsFound := false

	existingResults := make(map[string]string)
	orderedResults := []ResultEntry{}
	existingFile, err := os.Open(*fileFlag)
	if err != nil && !os.IsNotExist(err) {
		log.Println(fmt.Sprintf("Error opening existing file: %v", err))
		os.Exit(1)
	}
	if err == nil {
		defer existingFile.Close()
		scanner := bufio.NewScanner(existingFile)
		for scanner.Scan() {
			line := scanner.Text()
			var result map[string]interface{}
			if err := json.Unmarshal([]byte(line), &result); err == nil {
				if link, ok := result["link"].(string); ok {
					if position, exists := currentResultLinks[link]; exists {
						existingResults[link] = line
						orderedResults = append(orderedResults, ResultEntry{
							Position: position,
							Line:     line,
						})
					} else {
						title := "Unknown Title"
						for _, result := range searchResult.OrganicResults {
							if result.Link == link {
								title = result.Title
								break
							}
						}
						fmt.Printf("Deleted result: %s | %s\n", title, link)
						syslogWriter.Info(fmt.Sprintf("Deleted result: %s | %s", title, link))
					}
				}
			}
		}
	}

	orderedResults = sortResultsByPosition(orderedResults)

	for _, entry := range orderedResults {
		writer.WriteString(entry.Line + "\n")
	}

	newResults := []ResultEntry{}
	for _, result := range searchResult.OrganicResults {
		if _, exists := existingResults[result.Link]; !exists {
			jsonResult, err := json.Marshal(result)
			if err != nil {
				log.Printf("Error marshaling result: %v", err)
				continue
			}

			newResults = append(newResults, ResultEntry{
				Position: result.Position,
				Line:     string(jsonResult),
			})
			fmt.Printf("New result: %s | %s\n", result.Title, result.Link)
			syslogWriter.Info(fmt.Sprintf("New result: %s | %s", result.Title, result.Link))
			newResultsFound = true
		}
	}

	newResults = sortResultsByPosition(newResults)
	for _, entry := range newResults {
		writer.WriteString(entry.Line + "\n")
	}

	writer.Flush()
	outputFile.Close()

	err = os.Rename(tempFile, *fileFlag)
	if err != nil {
		log.Println(fmt.Sprintf("Error replacing file: %v", err))
		os.Exit(1)
	}

	if newResultsFound {
		os.Exit(2)
	}
}
