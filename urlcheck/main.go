package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		printUsage()
		os.Exit(1)
	}

	arg := os.Args[1]

	if strings.HasPrefix(arg, "-") {
		printUsage()
		os.Exit(0)
	}

	if len(arg) > 2048 {
		fmt.Fprintf(os.Stderr, "URL too long (max 2048 characters)\n")
		os.Exit(1)
	}

	// Validate and normalize URL
	targetURL := arg
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil || parsedURL.Host == "" {
		fmt.Fprintf(os.Stderr, "Invalid URL format\n")
		os.Exit(1)
	}

	// Protocol validation
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		fmt.Fprintf(os.Stderr, "Only HTTP and HTTPS protocols are supported\n")
		os.Exit(1)
	}

	if parsedURL.Scheme == "http" {
		fmt.Fprintf(os.Stderr, "Warning: Using insecure HTTP protocol\n")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).Dial,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				InsecureSkipVerify: false,
				CipherSuites: []uint16{
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
			},
			DisableKeepAlives:        true,
			DisableCompression:       false,
			MaxIdleConns:             0,
			IdleConnTimeout:          0,
			ResponseHeaderTimeout:    5 * time.Second,
			MaxResponseHeaderBytes:   32768, // 32KB limit
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Make HEAD request first for efficiency and security
	req, err := http.NewRequest("HEAD", targetURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			fmt.Fprintf(os.Stderr, "Request timeout\n")
		} else if strings.Contains(err.Error(), "connection refused") {
			fmt.Fprintf(os.Stderr, "Connection refused\n")
		} else if strings.Contains(err.Error(), "no such host") {
			fmt.Fprintf(os.Stderr, "DNS resolution failed\n")
		} else if strings.Contains(err.Error(), "too many redirects") {
			fmt.Fprintf(os.Stderr, "Too many redirects (max 10)\n")
		} else {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
		os.Exit(1)
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()
	if finalURL != targetURL {
		fmt.Printf("%d %s > %s\n", resp.StatusCode, targetURL, finalURL)
	} else {
		fmt.Printf("%d %s\n", resp.StatusCode, finalURL)
	}

	os.Exit(0)
}

func printUsage() {
	fmt.Printf("Usage: %s [url]\nDisplay URL HTTP status code\n", filepath.Base(os.Args[0]))
}
