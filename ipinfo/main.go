package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	args := os.Args
	if len(args) > 1 && args[1] == "-help" {
		fmt.Printf("Usage: %s [IP]\nGet IP info from ipinfo.io\n", args[0])
		return
	}

	client := createSecureClient()

	req, err := http.NewRequest(http.MethodGet,
		"https://ipinfo.io"+getPath(args), nil)
	if err != nil {
		die(err)
	}
	req.Header.Set("User-Agent", "curl/8.14.1")

	resp, err := client.Do(req)
	if err != nil {
		die(err)
	}
	defer resp.Body.Close()

	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		die(err)
	}
	fmt.Println()
}

func createSecureClient() *http.Client {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		InsecureSkipVerify: false,
		ClientAuth:         tls.NoClientCert,
		PreferServerCipherSuites: true,
		// Disable session tickets for perfect forward secrecy
		SessionTicketsDisabled: true,
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Limit redirects for security
			if len(via) >= 3 {
				return fmt.Errorf("Too many redirects")
			}
			return nil
		},
	}
}

func getPath(args []string) string {
	if len(args) > 1 {
		return "/" + args[1]
	}
	return ""
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
