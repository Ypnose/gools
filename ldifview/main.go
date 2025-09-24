package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type LDAPEntry struct {
	DN         string
	Attributes map[string][]string
}

type TreeNode struct {
	DN       string
	Children map[string]*TreeNode
	Entry    *LDAPEntry
}

func NewTreeNode(dn string) *TreeNode {
	return &TreeNode{
		DN:       dn,
		Children: make(map[string]*TreeNode),
	}
}

func parseLDIF(filename string) ([]*LDAPEntry, error) {
	var reader io.Reader

	if filename == "-" || filename == "" {
		reader = os.Stdin
	} else {
		file, err := os.Open(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %v", err)
		}
		defer file.Close()
		reader = file
	}

	var entries []*LDAPEntry
	var currentEntry *LDAPEntry
	var lastAttribute string
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		originalLine := scanner.Text()
		line := strings.TrimSpace(originalLine)

		if line == "" || strings.HasPrefix(line, "#") {
			if line == "" && currentEntry != nil {
				entries = append(entries, currentEntry)
				currentEntry = nil
				lastAttribute = ""
			}
			continue
		}

		if strings.HasPrefix(originalLine, " ") && currentEntry != nil && lastAttribute != "" {
			continuationValue := strings.TrimPrefix(originalLine, " ")

			if lastAttribute == "dn" {
				currentEntry.DN += continuationValue
			} else if currentEntry.Attributes[lastAttribute] != nil && len(currentEntry.Attributes[lastAttribute]) > 0 {
				lastIdx := len(currentEntry.Attributes[lastAttribute]) - 1
				currentEntry.Attributes[lastAttribute][lastIdx] += continuationValue
			}
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		attribute := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if strings.HasPrefix(value, ": ") {
			value = strings.TrimPrefix(value, " ")
		}

		if attribute == "dn" {
			if currentEntry != nil {
				entries = append(entries, currentEntry)
			}
			currentEntry = &LDAPEntry{
				DN:         value,
				Attributes: make(map[string][]string),
			}
			lastAttribute = attribute
		} else if currentEntry != nil {
			if currentEntry.Attributes[attribute] == nil {
				currentEntry.Attributes[attribute] = []string{}
			}
			currentEntry.Attributes[attribute] = append(currentEntry.Attributes[attribute], value)
			lastAttribute = attribute
		}
	}

	if currentEntry != nil {
		entries = append(entries, currentEntry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	return entries, nil
}

func buildTree(entries []*LDAPEntry) *TreeNode {
	nodes := make(map[string]*TreeNode)

	for _, entry := range entries {
		nodes[entry.DN] = NewTreeNode(entry.DN)
		nodes[entry.DN].Entry = entry
	}

	var roots []*TreeNode

	for _, entry := range entries {
		node := nodes[entry.DN]
		parentDN := getParentDN(entry.DN)

		if parentDN == "" || nodes[parentDN] == nil {
			roots = append(roots, node)
		} else {
			parent := nodes[parentDN]
			parent.Children[entry.DN] = node
		}
	}

	if len(roots) > 1 {
		virtualRoot := NewTreeNode("(multiple roots)")
		for _, root := range roots {
			virtualRoot.Children[root.DN] = root
		}
		return virtualRoot
	} else if len(roots) == 1 {
		return roots[0]
	}

	return nil
}

func getParentDN(dn string) string {
	parts := strings.Split(dn, ",")
	if len(parts) <= 1 {
		return ""
	}
	return strings.Join(parts[1:], ",")
}

func stripParentDN(dn, parentDN string) string {
	if parentDN == "" {
		return dn
	}
	suffix := "," + parentDN
	if strings.HasSuffix(dn, suffix) {
		return strings.TrimSuffix(dn, suffix)
	}
	return dn
}

func printTree(node *TreeNode, prefix string, isLast bool, isRoot bool, parentDN string) {
	if node == nil {
		return
	}

	if node.DN == "(multiple roots)" {
		fmt.Println("Multiple root entries:")
	} else {
		displayDN := stripParentDN(node.DN, parentDN)

		if isRoot {
			fmt.Printf("%s\n", displayDN)
		} else {
			connector := "├─"
			if isLast {
				connector = "└─"
			}
			fmt.Printf("%s%s%s\n", prefix, connector, displayDN)
		}
	}

	childPrefix := prefix
	if node.DN != "(multiple roots)" && !isRoot {
		if isLast {
			childPrefix += "  "
		} else {
			childPrefix += "│ "
		}
	}

	var childDNs []string
	for dn := range node.Children {
		childDNs = append(childDNs, dn)
	}
	sort.Strings(childDNs)

	for i, dn := range childDNs {
		child := node.Children[dn]
		isLastChild := i == len(childDNs)-1
		printTree(child, childPrefix, isLastChild, false, node.DN)
	}
}

func printStats(entries []*LDAPEntry) {
	fmt.Printf("Total entries: %d\n", len(entries))

	objectClasses := make(map[string]int)
	for _, entry := range entries {
		if classes, exists := entry.Attributes["objectClass"]; exists {
			for _, class := range classes {
				objectClasses[class]++
			}
		}
	}

	if len(objectClasses) > 0 {
		fmt.Println("\nObject classes:")
		var classes []string
		for class := range objectClasses {
			classes = append(classes, class)
		}
		sort.Strings(classes)

		for _, class := range classes {
			fmt.Printf("  %s: %d\n", class, objectClasses[class])
		}
	}
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ldifview [file]\n")
		fmt.Fprintf(os.Stderr, "Display LDAP directory structure from LDIF file\n")
	}

	flag.Parse()
	args := flag.Args()

	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" {
			flag.Usage()
			os.Exit(0)
		}
	}

	var filename string
	if len(args) == 0 {
		filename = "-" // stdin
	} else {
		filename = args[0]
	}

	entries, err := parseLDIF(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing LDIF: %v\n", err)
		os.Exit(1)
	}

	if len(entries) == 0 {
		fmt.Println("No entries found")
		return
	}

	root := buildTree(entries)
	if root == nil {
		fmt.Println("Could not build directory tree")
		return
	}

	fmt.Println("LDAP Directory Structure:")
	fmt.Println("========================")
	printTree(root, "", true, true, "")

	printStats(entries)
}
