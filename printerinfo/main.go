package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"encoding/hex"
	"sort"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
)

const (
	timeout       = 5 * time.Second
	maxConcurrent = 10
)

type Supply struct {
	Name  string
	Level interface{}
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: printsnmp [-community string] [-version 1|2c] [printer]\n\n")
		fmt.Fprintf(os.Stderr, "Retrieves printer information via SNMPv1 and SNMPv2c\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -community string\n")
		fmt.Fprintf(os.Stderr, "        SNMP community string (default \"public\")\n")
		fmt.Fprintf(os.Stderr, "  -version string\n")
		fmt.Fprintf(os.Stderr, "        SNMP version (1 or 2c) (default \"2c\")\n")
	}

	version := flag.String("version", "2c", "SNMP version (1 or 2c)")
	community := flag.String("community", "public", "SNMP community string")
	help := flag.Bool("help", false, "Show usage information")
	flag.Parse()

	if *help || flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	if !utf8.ValidString(*community) {
		log.Fatal("Invalid community string")
	}

	target := flag.Arg(0)
	if net.ParseIP(target) == nil {
		addrs, err := net.LookupHost(target)
		if err != nil || len(addrs) == 0 {
			log.Fatalf("Invalid target address: %v", err)
		}
		target = addrs[0]
	}

	snmp := &gosnmp.GoSNMP{
		Target:    target,
		Port:      161,
		Community: *community,
		Version:   getSnmpVersion(*version),
		Timeout:   timeout,
	}

	err := snmp.Connect()
	if err != nil {
		log.Fatalf("Connect error: %v", err)
	}
	defer snmp.Conn.Close()

	basicInfo, err := getBasicInfo(snmp)
	if err != nil {
		log.Fatalf("Failed to get basic info: %v", err)
	}
	fmt.Print(basicInfo)

	supplies, err := getSupplies(snmp)
	if err != nil {
		log.Printf("Warning: Failed to get supplies info: %v", err)
	}

	sort.Slice(supplies, func(i, j int) bool {
		return supplies[i].Name < supplies[j].Name
	})

	for _, supply := range supplies {
		fmt.Printf("Supply: %s, level: %v\n", supply.Name, supply.Level)
	}
}

func getBasicInfo(snmp *gosnmp.GoSNMP) (string, error) {
	result, err := snmp.Get([]string{
		"1.3.6.1.2.1.1.5.0",         // Name
		"1.3.6.1.2.1.25.3.2.1.3.1", // Model
		"1.3.6.1.2.1.1.6.0",     // Location
	})
	if err != nil {
		return "", fmt.Errorf("SNMP Get error: %v", err)
	}

	return fmt.Sprintf("Name: %s\nModel: %s\nLocation: %s\n",
		decodeValue(result.Variables[0].Value),
		decodeValue(result.Variables[1].Value),
		decodeValue(result.Variables[2].Value)), nil
}

func getSupplies(snmp *gosnmp.GoSNMP) ([]Supply, error) {
	var supplies []Supply
	var mu sync.Mutex

	err := snmp.Walk("1.3.6.1.2.1.43.11.1.1.6.1", func(pdu gosnmp.SnmpPDU) error {
		oidParts := strings.Split(pdu.Name, ".")
		if len(oidParts) == 0 {
			return nil
		}

		index := oidParts[len(oidParts)-1]
		name := decodeValue(pdu.Value)

		levelOid := "1.3.6.1.2.1.43.11.1.1.9.1." + index
		result, err := snmp.Get([]string{levelOid})
		if err != nil {
			return nil
		}

		if len(result.Variables) > 0 && result.Variables[0].Value != nil {
			mu.Lock()
			supplies = append(supplies, Supply{
				Name:  name,
				Level: result.Variables[0].Value,
			})
			mu.Unlock()
		}
		return nil
	})

	return supplies, err
}

func getSnmpVersion(version string) gosnmp.SnmpVersion {
	switch version {
	case "1":
		return gosnmp.Version1
	case "2c":
		return gosnmp.Version2c
	default:
		log.Fatalf("Unsupported SNMP version: %s", version)
		return gosnmp.Version2c
	}
}

func decodeValue(value interface{}) string {
	if value == nil {
		return "N/A"
	}

	switch v := value.(type) {
	case string:
		if strings.HasPrefix(v, "0x") {
			decoded, err := hex.DecodeString(v[2:])
			if err == nil {
				return string(decoded)
			}
		}
		return v
	case []byte:
		return string(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}
