package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	CheckURL   = "https://pushover.net/"
	URL        = "https://api.pushover.net/1/messages.json"
	maxRetries = 4

	// Default credentials - can be set directly here
	defaultUser  = "" // Add your user ID here if desired
	defaultToken = "" // Add your token here if desired
)

var transport = &http.Transport{
	TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
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
			log.Printf("Network check attempt %d/%d", i+1, maxRetries)
		}

		resp, err := client.Get(CheckURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return true
		}

		if debug {
			log.Println("Network check failed")
			log.SetFlags(0)
		}

		if i < maxRetries-1 {
			time.Sleep(30 * time.Second)
		}
	}
	return false
}

func main() {
	title := flag.String("title", "", "Title of the message (required)")
	message := flag.String("message", "", "Content of the message (required)")
	user := flag.String("user", defaultUser, "Username for authentication (required if not set in code)")
	token := flag.String("token", defaultToken, "Authentication token (required if not set in code)")
	debug := flag.Bool("debug", false, "Enable debug logging")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s\n", os.Args[0])
		flag.PrintDefaults()
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
