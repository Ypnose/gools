package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	BROADCAST_IP = "255.255.255.255"
	UDP_PORT = 9
	MAGIC_PACKET_SIZE = 102 // 6 bytes of 0xFF + 16 * 6 bytes MAC = 102
	MAC_ADDRESS_LENGTH = 6
	CONNECT_TIMEOUT = 5 * time.Second
)

var (
	macRegex = regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)
)

// validateMAC validates MAC address in format aa:bb:cc:dd:ee:ff
func validateMAC(mac string) bool {
	if len(mac) != 17 { // aa:bb:cc:dd:ee:ff is exactly 17 characters
		return false
	}

	return macRegex.MatchString(mac)
}

func parseMAC(mac string) ([]byte, error) {
	// Remove colons and convert to lowercase for consistency
	cleanMAC := strings.ReplaceAll(strings.ToLower(mac), ":", "")

	if len(cleanMAC) != 12 {
		return nil, fmt.Errorf("Invalid MAC address length after cleaning")
	}

	// Use hex package for secure parsing
	macBytes, err := hex.DecodeString(cleanMAC)
	if err != nil {
		return nil, fmt.Errorf("Invalid hex characters in MAC address: %v", err)
	}

	// Double-check the length
	if len(macBytes) != MAC_ADDRESS_LENGTH {
		return nil, fmt.Errorf("Parsed MAC address has invalid length")
	}

	return macBytes, nil
}

// createMagicPacket creates the magic packet for Wake-on-LAN
func createMagicPacket(macBytes []byte) []byte {
	// Pre-allocate packet with known size
	packet := make([]byte, MAGIC_PACKET_SIZE)

	// First 6 bytes are 0xFF
	for i := 0; i < 6; i++ {
		packet[i] = 0xFF
	}

	// Next 96 bytes are 16 repetitions of the MAC address
	for i := 0; i < 16; i++ {
		copy(packet[6+i*MAC_ADDRESS_LENGTH:], macBytes)
	}

	return packet
}

// sendMagicPacket sends the magic packet via UDP with proper error handling
func sendMagicPacket(mac string) error {
	// Parse MAC address first
	macBytes, err := parseMAC(mac)
	if err != nil {
		return fmt.Errorf("Failed to parse MAC address: %v", err)
	}

	// Create UDP address
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", BROADCAST_IP, UDP_PORT))
	if err != nil {
		return fmt.Errorf("Failed to resolve UDP address: %v", err)
	}

	// Create UDP connection with timeout
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("Failed to create UDP connection: %v", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close connection: %v\n", closeErr)
		}
	}()

	// Set write timeout to prevent hanging
	if err := conn.SetWriteDeadline(time.Now().Add(CONNECT_TIMEOUT)); err != nil {
		return fmt.Errorf("Failed to set write deadline: %v", err)
	}

	packet := createMagicPacket(macBytes)
	bytesWritten, err := conn.Write(packet)
	if err != nil {
		return fmt.Errorf("Failed to send packet: %v", err)
	}

	// Verify all bytes were written
	if bytesWritten != MAGIC_PACKET_SIZE {
		return fmt.Errorf("Incomplete packet sent: wrote %d bytes, expected %d", bytesWritten, MAGIC_PACKET_SIZE)
	}

	fmt.Printf("Sending magic packet to %s:%d with MAC address %s\n", BROADCAST_IP, UDP_PORT, mac)

	return nil
}

func printUsage() {
	fmt.Println("usage: wakeonlan [MAC address]")
	fmt.Println("Sends magic packets to Wake-on-LAN enabled ethernet adapters")
}

func validateArgs() (string, error) {
	if len(os.Args) < 2 {
		return "", fmt.Errorf("No MAC address provided")
	}

	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-") {
			return "", fmt.Errorf("Unsupported flag: %s", arg)
		}
	}

	// Only process the first argument, ignore others for security
	mac := strings.TrimSpace(os.Args[1])

	if mac == "" {
		return "", fmt.Errorf("Empty MAC address provided")
	}

	if !validateMAC(mac) {
		return "", fmt.Errorf("Invalid MAC address format: %s", mac)
	}

	return mac, nil
}

func main() {
	mac, err := validateArgs()
	if err != nil {
		if strings.Contains(err.Error(), "Unsupported flag") || strings.Contains(err.Error(), "Invalid MAC address format") {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		printUsage()
		os.Exit(1)
	}

	// Send magic packet
	if err := sendMagicPacket(mac); err != nil {
		fmt.Fprintf(os.Stderr, "Error sending magic packet: %v\n", err)
		os.Exit(1)
	}
}
