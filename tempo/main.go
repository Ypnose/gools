package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
)

type TempoResponse struct {
	DateJour string `json:"dateJour"`
	CodeJour int    `json:"codeJour"`
}

var colors = map[int]string{1: "BLEU", 2: "BLANC", 3: "ROUGE"}

func main() {
	var auj, dem bool
	flag.BoolVar(&auj, "auj", false, "affiche uniquement la couleur d'aujourd'hui")
	flag.BoolVar(&dem, "dem", false, "affiche uniquement la couleur de demain")
	help := flag.Bool("help", false, "affiche l'aide")
	flag.Parse()

	if *help {
		fmt.Printf("Usage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Println("\nSans option, affiche les couleurs pour aujourd'hui et demain avec leurs dates")
		return
	}

	switch {
	case auj:
		printColor("today")
	case dem:
		printColor("tomorrow")
	default:
		printFull("today", "aujourd'hui")
		printFull("tomorrow", "demain")
	}
}

func getTempoData(endpoint string) (*TempoResponse, error) {
	resp, err := http.Get("https://www.api-couleur-tempo.fr/api/jourTempo/" + endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var tempo TempoResponse
	if err := json.NewDecoder(resp.Body).Decode(&tempo); err != nil {
		return nil, err
	}
	return &tempo, nil
}

func printColor(endpoint string) {
	if tempo, err := getTempoData(endpoint); err == nil {
		if color, ok := colors[tempo.CodeJour]; ok {
			fmt.Println(color)
		}
	}
}

func printFull(endpoint, period string) {
	if tempo, err := getTempoData(endpoint); err == nil {
		if color, ok := colors[tempo.CodeJour]; ok {
			fmt.Printf("Tempo %s (%s): %s\n", period, tempo.DateJour, color)
		}
	}
}
