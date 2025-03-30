package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log/syslog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"time"
)

// You can set your API key directly here
const DefaultAPIKey = ""

// Result represents a single search result from the organic_results
type Result struct {
	Position      int    `json:"position"`
	Title         string `json:"title"`
	Link          string `json:"link"`
	RedirectLink  string `json:"redirect_link"`
	DisplayedLink string `json:"displayed_link"`
	Snippet       string `json:"snippet"`
	Source        string `json:"source"`
}

// Response represents the API response structure
type Response struct {
	OrganicResults []APIResult `json:"organic_results"`
}

// APIResponse represents the raw API response
type APIResult struct {
	Position      int    `json:"position"`
	Title         string `json:"title"`
	Link          string `json:"link"`
	RedirectLink  string `json:"redirect_link"`
	DisplayedLink string `json:"displayed_link"`
	Favicon       string `json:"favicon,omitempty"`
	Snippet       string `json:"snippet"`
	Source        string `json:"source"`
}

func main() {
	binaryName := os.Args[0]

	// Set up logging to syslog
	syslogWriter, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_USER, binaryName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up syslog: %v\n", err)
	} else {
		defer syslogWriter.Close()
	}
	var (
		query    string
		outFile  string
		location string
		verbose  bool
	)

	flag.StringVar(&query, "query", "", "")
	flag.StringVar(&outFile, "file", "", "")
	flag.StringVar(&location, "location", "Paris,Paris,Ile-de-France,France", "")
	flag.BoolVar(&verbose, "verbose", false, "")

	usageMessage := fmt.Sprintf("Usage: %s [-file FILE] [-query QUERY] [-location LOCATION] [-verbose]\n", binaryName)
	
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usageMessage)
	}

	flag.Parse()

	// Check for required arguments
	if query == "" || outFile == "" {
		fmt.Fprint(os.Stderr, usageMessage)
		fmt.Fprintf(os.Stderr, "Error: Both -file and -query are required\n")
		os.Exit(1)
	}

	// Get API key from environment variable or use default
	apiKey := os.Getenv("SERPAPI_KEY")
	if apiKey == "" {
		// Use the default API key if set in the code
		apiKey = DefaultAPIKey
		if apiKey == "" {
			fmt.Fprintf(os.Stderr, "Error: SERPAPI_KEY environment variable is not set and no default API key is provided in the code\n")
			os.Exit(1)
		}
	}

	// Configure TLS to only use TLS 1.3 with specific cipher suites
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	// Configure HTTP client with connection pooling and timeouts
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		MaxIdleConns: 10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout: 90 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout: 30 * time.Second,
	}

	// Build request URL with query parameters
	baseURL := "https://serpapi.com/search"
	params := url.Values{}
	params.Add("api_key", apiKey)
	params.Add("engine", "google")
	params.Add("q", query)
	params.Add("location", location)
	params.Add("google_domain", "google.com")
	params.Add("gl", "us")
	params.Add("hl", "en")
	params.Add("safe", "off")
	params.Add("filter", "0")
	params.Add("num", "200")
	params.Add("device", "mobile")
	params.Add("cr", "countryUS|countryFR|countryBE|countryDE|countryBR|countryRU|countryJP|countryLU|countryUK|countryCN")
	params.Add("lr", "lang_en|lang_fr|lang_de|lang_ru|lang_ja|lang_pt|lang_zh-CN|lang_zh-TW")

	// Construct final URL with parameters
	requestURL := baseURL + "?" + params.Encode()

	// Make the request
	resp, err := client.Get(requestURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error making request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Error: API returned status code %d\n", resp.StatusCode)
		os.Exit(1)
	}

	// Read and parse response
	var response Response
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&response); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	// Convert API results to our Result format (without favicon)
	newResults := make([]Result, 0, len(response.OrganicResults))
	for _, apiResult := range response.OrganicResults {
		newResults = append(newResults, Result{
			Position:      apiResult.Position,
			Title:         apiResult.Title,
			Link:          apiResult.Link,
			RedirectLink:  apiResult.RedirectLink,
			DisplayedLink: apiResult.DisplayedLink,
			Snippet:       apiResult.Snippet,
			Source:        apiResult.Source,
		})
	}
	existingResults := loadExistingResults(outFile)

	// Find added and deleted results
	added, deleted := compareResults(existingResults, newResults)

	// If changes detected, update the file
	if len(added) > 0 || len(deleted) > 0 {
		// Display messages for deleted results
		for _, result := range deleted {
			msg := fmt.Sprintf("Deleted result: %s | %s", result.Title, result.Link)
			fmt.Println(msg)
			if syslogWriter != nil {
				syslogWriter.Notice(msg)
			}
		}

		// Display messages for added results
		for _, result := range added {
			msg := fmt.Sprintf("New result: %s | %s", result.Title, result.Link)
			fmt.Println(msg)
			if syslogWriter != nil {
				syslogWriter.Notice(msg)
			}
		}

		// Create final result set
		finalResults := make([]Result, 0)
		for _, result := range newResults {
			finalResults = append(finalResults, result)
		}

		// Sort by position
		sort.Slice(finalResults, func(i, j int) bool {
			return finalResults[i].Position < finalResults[j].Position
		})

		// Save results
		saveResults(outFile, finalResults)

		// Display summary
		summary := fmt.Sprintf("Changes: %d results deleted, %d results added, %d existing results, %d total results",
			len(deleted), len(added), len(newResults)-len(added), len(newResults))
		fmt.Println(summary)
		if syslogWriter != nil {
			syslogWriter.Notice(summary)
		}
		
		// Display request URL if verbose mode is enabled
		if verbose {
			fmt.Printf("Request URL: %s\n", requestURL)
		}

		// Exit with code 2 if changes were detected
		os.Exit(2)
	}
}

// loadExistingResults loads results from the specified file
func loadExistingResults(filePath string) []Result {
	file, err := os.Open(filePath)
	if os.IsNotExist(err) {
		return []Result{}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not open existing file: %v\n", err)
		return []Result{}
	}
	defer file.Close()

	var results []Result
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result Result
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Invalid JSON in file: %v\n", err)
			continue
		}
		results = append(results, result)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Error reading file: %v\n", err)
	}

	return results
}

// saveResults saves results to the specified file
func saveResults(filePath string, results []Result) {
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for _, result := range results {
		resultJSON, err := json.Marshal(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding result: %v\n", err)
			continue
		}
		writer.Write(resultJSON)
		writer.WriteString("\n")
	}

	writer.Flush()
}

// compareResults compares existing and new results to find added and deleted items
func compareResults(existing, new []Result) (added, deleted []Result) {
	// Build maps for quick lookup
	existingMap := make(map[string]Result)
	for _, result := range existing {
		existingMap[result.Link] = result
	}

	newMap := make(map[string]Result)
	for _, result := range new {
		newMap[result.Link] = result
	}

	// Find added results
	for link, result := range newMap {
		if _, exists := existingMap[link]; !exists {
			added = append(added, result)
		}
	}

	// Find deleted results
	for link, result := range existingMap {
		if _, exists := newMap[link]; !exists {
			deleted = append(deleted, result)
		}
	}

	return added, deleted
}
