package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	CheckURL   = "https://api.pushover.net/"
	URL        = "https://api.pushover.net/1/messages.json"
	maxRetries = 4

	// Default credentials - can be set directly here
	defaultUser  = "" // Add your user ID here if desired
	defaultToken = "" // Add your token here if desired
)

var transport = &http.Transport{
	TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	},
	ForceAttemptHTTP2: true,
}

var client = &http.Client{
	Timeout:       10 * time.Second,
	Transport:     transport,
	CheckRedirect: nil,
}

func init() {
	log.SetFlags(0)
}

func checkNetworkAccess(debug bool) bool {
	for i := 0; i < maxRetries; i++ {
		if debug {
			log.SetFlags(log.LstdFlags)
			log.Printf("Network check attempt to %s (%d/%d)", CheckURL, i+1, maxRetries)
		}

		resp, err := client.Get(CheckURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return true
		}

		if debug {
			if err != nil {
				log.Printf("Network check failed: %v", err)
			} else {
				log.Printf("Network check failed: HTTP %d", resp.StatusCode)
			}
			log.SetFlags(0)
		}

		if i < maxRetries-1 {
			time.Sleep(30 * time.Second)
		}
	}
	return false
}

func main() {
	title := flag.String("title", "", "")
	message := flag.String("message", "", "")
	user := flag.String("user", defaultUser, "")
	token := flag.String("token", defaultToken, "")
	debug := flag.Bool("debug", false, "")

	flag.Usage = func() {
		log.Printf("Usage: %s\n", os.Args[0])
		log.Println("  -title string")
		log.Println("    Title of the message (required)")
		log.Println("  -message string")
		log.Println("    Content of the message (required)")
		log.Println("  -user string")
		log.Println("    Username for authentication (required if not set in code)")
		log.Println("  -token string")
		log.Println("    Authentication token (required if not set in code)")
		log.Println("  -debug")
		log.Println("    Enable debug logging")
	}
	flag.Parse()

	missing := []string{}
	if *title == "" {
		missing = append(missing, "title")
	}
	if *message == "" {
		missing = append(missing, "message")
	}
	if *user == "" {
		missing = append(missing, "user")
	}
	if *token == "" {
		missing = append(missing, "token")
	}

	if len(missing) > 0 {
		log.Printf("Missing required parameters: %v", missing)
		flag.Usage()
		os.Exit(1)
	}

	if !checkNetworkAccess(*debug) {
		os.Exit(1)
	}

	data := url.Values{
		"user":      {*user},
		"token":     {*token},
		"timestamp": {strconv.FormatInt(time.Now().Unix(), 10)},
		"title":     {*title},
		"message":   {*message},
	}

	if os.Getenv("PUSH_PRIORITY_HIGH") == "1" {
		data.Set("priority", "1")
	} else if os.Getenv("PUSH_PRIORITY_CRITICAL") == "1" {
		data.Set("priority", "2")
		data.Set("retry", "60")
		data.Set("expire", "7200")
	}

	resp, err := client.PostForm(URL, data)
	if err != nil {
		log.Fatal("Request failed")
	}
	defer resp.Body.Close()

	if *debug {
		log.Printf("Response Status: %s", resp.Status)
	}
}
