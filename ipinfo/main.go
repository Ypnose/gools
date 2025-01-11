package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	args := os.Args
	if len(args) > 1 && args[1] == "-help" {
		fmt.Printf("Usage: %s [IP]\nGet IP info from ipinfo.io\n", args[0])
		return
	}

	req, err := http.NewRequest(http.MethodGet,
		"http://ipinfo.io"+getPath(args), nil)
	if err != nil {
		die(err)
	}
	req.Header.Set("User-Agent", "curl/8.11.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		die(err)
	}
	defer resp.Body.Close()

	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		die(err)
	}
	fmt.Println()
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
