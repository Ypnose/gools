package main

import (
	"compress/gzip"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DMARC Report Structure
type Report struct {
	XMLName        xml.Name       `xml:"feedback"`
	ReportMetadata ReportMetadata `xml:"report_metadata"`
	PolicyPublished Policy        `xml:"policy_published"`
	Records        []Record       `xml:"record"`
}

type ReportMetadata struct {
	OrgName          string    `xml:"org_name"`
	Email            string    `xml:"email"`
	ExtraContactInfo string    `xml:"extra_contact_info"`
	ReportID         string    `xml:"report_id"`
	DateRange        DateRange `xml:"date_range"`
}

type DateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

type Policy struct {
	Domain string `xml:"domain"`
	ADKIM  string `xml:"adkim"`
	ASPF   string `xml:"aspf"`
	P      string `xml:"p"`
	SP     string `xml:"sp"`
	PCT    int    `xml:"pct"`
}

type Record struct {
	Row         Row         `xml:"row"`
	Identifiers Identifiers `xml:"identifiers"`
	AuthResults AuthResults `xml:"auth_results"`
}

type Row struct {
	SourceIP    string `xml:"source_ip"`
	Count       int    `xml:"count"`
	Disposition string `xml:"policy_evaluated>disposition"`
	DKIM        string `xml:"policy_evaluated>dkim"`
	SPF         string `xml:"policy_evaluated>spf"`
}

type Identifiers struct {
	HeaderFrom   string `xml:"header_from"`
	EnvelopeTo   string `xml:"envelope_to"`
	EnvelopeFrom string `xml:"envelope_from"`
}

type AuthResults struct {
	DKIM DKIMResult `xml:"dkim"`
	SPF  SPFResult  `xml:"spf"`
}

type DKIMResult struct {
	Domain   string `xml:"domain"`
	Result   string `xml:"result"`
	Selector string `xml:"selector"`
}

type SPFResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

func formatTimestamp(timestamp int64) string {
	t := time.Unix(timestamp, 0)
	return t.Format("2006-01-02 15:04:05")
}

// Resolve IP to hostname, return IP if resolution fails
func resolveIP(ip string) string {
	if ip == "" {
		return ""
	}

	// Validate IP before attempting lookup to prevent potential security issues
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ip
	}

	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ip
	}

	// Remove trailing dot from hostname and return the first entry
	return strings.TrimSuffix(names[0], ".")
}

func main() {
	flag.Usage = func() {
		programName := filepath.Base(os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage: %s [file]\n", programName)
		fmt.Fprintf(os.Stderr, "Display DMARC reports\n")
	}

	help := flag.Bool("help", false, "Show help")
	flag.Parse()

	if *help || flag.NArg() < 1 {
		flag.Usage()
		os.Exit(0)
	}

	filename := flag.Arg(0)

	file, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	var reader io.Reader = file

	// Check if file is gzipped
	if strings.HasSuffix(strings.ToLower(filename), ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening gzip file: %v\n", err)
			os.Exit(1)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading data: %v\n", err)
		os.Exit(1)
	}

	var report Report
	err = xml.Unmarshal(data, &report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing XML: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("DMARC Report Summary")
	fmt.Println("====================")
	fmt.Printf("Organization: %s\n", report.ReportMetadata.OrgName)
	fmt.Printf("Report ID: %s\n", report.ReportMetadata.ReportID)
	fmt.Printf("Date Range: %s to %s\n",
		formatTimestamp(report.ReportMetadata.DateRange.Begin),
		formatTimestamp(report.ReportMetadata.DateRange.End))
	fmt.Printf("Domain: %s\n", report.PolicyPublished.Domain)
	fmt.Printf("Policy: p=%s, sp=%s, adkim=%s, aspf=%s, pct=%d\n\n",
		report.PolicyPublished.P,
		report.PolicyPublished.SP,
		report.PolicyPublished.ADKIM,
		report.PolicyPublished.ASPF,
		report.PolicyPublished.PCT)

	// Column sizes
	sourceIPWidth := 39     // Max IPv6 address length or hostname
	countWidth := 8
	dispositionWidth := 12
	dkimWidth := 10
	spfWidth := 10
	fromWidth := 25
	toWidth := 25
	dkimResultWidth := 15
	spfResultWidth := 15

	fmt.Printf("%-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n",
		sourceIPWidth, "Source",
		countWidth, "Count",
		dispositionWidth, "Disposition",
		dkimWidth, "DKIM",
		spfWidth, "SPF",
		fromWidth, "From",
		toWidth, "To",
		dkimResultWidth, "DKIM Result",
		spfResultWidth, "SPF Result")

	totalWidth := sourceIPWidth + countWidth + dispositionWidth + dkimWidth +
		spfWidth + fromWidth + toWidth + dkimResultWidth + spfResultWidth + 8 // Add 8 for spaces (one more column)
	fmt.Println(strings.Repeat("-", totalWidth))

	for _, record := range report.Records {
		// Resolve IP to hostname or keep IP if no hostname found
		sourceHost := resolveIP(record.Row.SourceIP)

		// Truncate hostname if too long, preserving the width constraint
		if len(sourceHost) > sourceIPWidth {
			sourceHost = sourceHost[:sourceIPWidth-3] + "..."
		}

		// Ensure values are not too long for their columns
		headerFrom := record.Identifiers.HeaderFrom
		if len(headerFrom) > fromWidth {
			headerFrom = headerFrom[:fromWidth-3] + "..."
		}

		envelopeTo := record.Identifiers.EnvelopeTo
		if len(envelopeTo) > toWidth {
			envelopeTo = envelopeTo[:toWidth-3] + "..."
		}

		fmt.Printf("%-*s %-*d %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n",
			sourceIPWidth, sourceHost,
			countWidth, record.Row.Count,
			dispositionWidth, record.Row.Disposition,
			dkimWidth, record.Row.DKIM,
			spfWidth, record.Row.SPF,
			fromWidth, headerFrom,
			toWidth, envelopeTo,
			dkimResultWidth, record.AuthResults.DKIM.Result,
			spfResultWidth, record.AuthResults.SPF.Result)
	}
}
