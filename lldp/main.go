package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	ETH_P_LLDP          = 0x88CC
	ETH_P_8021Q         = 0x8100
	LLDP_TLV_END        = 0
	LLDP_TLV_CHASSIS_ID = 1
	LLDP_TLV_PORT_ID    = 2
	LLDP_TLV_TTL        = 3
	LLDP_TLV_PORT_DESC  = 4
	LLDP_TLV_SYS_NAME   = 5
	LLDP_TLV_SYS_DESC   = 6
	MAX_TLV_LENGTH      = 511
	MAX_STRING_LENGTH   = 255
	MAX_TLV_ITERATIONS  = 100
)

type LLDPInfo struct {
	Interface  string
	ChassisID  string
	PortID     string
	SystemName string
	PortDesc   string
	SystemDesc string
}

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "This program must be run as root")
		os.Exit(1)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting interfaces: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Listening for LLDP packets (waiting up to 30 seconds)...")
	fmt.Println()

	timeout := time.After(30 * time.Second)
	results := make(chan LLDPInfo, 10)
	done := make(chan bool)

	activeListeners := 0
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := iface.Name
		if (len(name) >= 4 && name[:4] == "bond") || (len(name) >= 2 && name[:2] == "br") {
			continue
		}
		activeListeners++
		go listenOnInterface(iface, results, done)
	}

	if activeListeners == 0 {
		fmt.Println("No suitable interfaces found")
		return
	}

	seen := make(map[string]bool)

	for {
		select {
		case info := <-results:
			if info.ChassisID == "" || info.PortID == "" {
				continue
			}
			key := info.Interface + "|" + info.ChassisID + "|" + info.PortID
			if !seen[key] {
				seen[key] = true
				printLLDPInfo(info)
			}
		case <-timeout:
			return
		case <-done:
			activeListeners--
			if activeListeners == 0 {
				return
			}
		}
	}
}

func listenOnInterface(iface net.Interface, results chan<- LLDPInfo, done chan<- bool) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Panic on %s: %v\n", iface.Name, r)
		}
		done <- true
	}()

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ETH_P_LLDP)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Socket error on %s: %v\n", iface.Name, err)
		return
	}
	defer syscall.Close(fd)

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(ETH_P_LLDP),
		Ifindex:  iface.Index,
	}

	if err := syscall.Bind(fd, &addr); err != nil {
		fmt.Fprintf(os.Stderr, "Bind error on %s: %v\n", iface.Name, err)
		return
	}

	tv := syscall.Timeval{Sec: 31, Usec: 0}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	buf := make([]byte, 9000)

	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return
		}

		if n < 14 {
			continue
		}

		headerSize := 14
		if n >= 16 {
			etherType := binary.BigEndian.Uint16(buf[12:14])
			if etherType == ETH_P_8021Q {
				headerSize = 18
			}
		}

		if n <= headerSize {
			continue
		}

		info := parseLLDP(buf[headerSize:n])
		if info != nil {
			info.Interface = iface.Name
			select {
			case results <- *info:
			default:
			}
		}
	}
}

func parseLLDP(data []byte) *LLDPInfo {
	if len(data) < 4 {
		return nil
	}

	info := &LLDPInfo{}
	offset := 0
	haveChassis := false
	havePort := false
	haveTTL := false
	seenEnd := false

	for i := 0; i < MAX_TLV_ITERATIONS && offset+2 <= len(data); i++ {
		tlvHeader := binary.BigEndian.Uint16(data[offset:])
		tlvType := tlvHeader >> 9
		tlvLength := int(tlvHeader & 0x1FF)

		if tlvLength > MAX_TLV_LENGTH {
			return nil
		}

		offset += 2

		if offset+tlvLength > len(data) {
			return nil
		}

		tlvValue := data[offset : offset+tlvLength]
		offset += tlvLength

		switch tlvType {
		case LLDP_TLV_END:
			seenEnd = true
			break
		case LLDP_TLV_CHASSIS_ID:
			haveChassis = true
			if tlvLength > 1 && tlvLength <= MAX_STRING_LENGTH {
				info.ChassisID = formatChassisID(tlvValue)
			}
		case LLDP_TLV_PORT_ID:
			havePort = true
			if tlvLength > 1 && tlvLength <= MAX_STRING_LENGTH {
				info.PortID = formatPortID(tlvValue)
			}
		case LLDP_TLV_TTL:
			if tlvLength == 2 {
				haveTTL = true
			} else {
				return nil
			}
		case LLDP_TLV_PORT_DESC:
			if tlvLength > 0 && tlvLength <= MAX_STRING_LENGTH {
				info.PortDesc = sanitizeString(tlvValue)
			}
		case LLDP_TLV_SYS_NAME:
			if tlvLength > 0 && tlvLength <= MAX_STRING_LENGTH {
				info.SystemName = sanitizeString(tlvValue)
			}
		case LLDP_TLV_SYS_DESC:
			if tlvLength > 0 && tlvLength <= MAX_STRING_LENGTH {
				info.SystemDesc = sanitizeString(tlvValue)
			}
		}

		if seenEnd {
			break
		}
	}

	if !seenEnd || !haveChassis || !havePort || !haveTTL {
		return nil
	}

	return info
}

func sanitizeString(data []byte) string {
	if len(data) == 0 || len(data) > MAX_STRING_LENGTH {
		return ""
	}

	if !utf8.Valid(data) {
		result := make([]byte, 0, len(data))
		for _, b := range data {
			if (b >= 32 && b <= 126) || b == '\n' || b == '\t' {
				result = append(result, b)
			}
		}
		return string(result)
	}

	result := make([]rune, 0, len(data))
	for _, r := range string(data) {
		if unicode.IsPrint(r) || r == '\n' || r == '\t' {
			result = append(result, r)
		}
	}
	return string(result)
}

func formatChassisID(data []byte) string {
	if len(data) < 2 || len(data) > MAX_STRING_LENGTH {
		return ""
	}
	subtype := data[0]
	value := data[1:]

	switch subtype {
	case 4:
		if len(value) == 6 {
			return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				value[0], value[1], value[2], value[3], value[4], value[5])
		}
	case 7:
		return sanitizeString(value)
	}
	return sanitizeString(value)
}

func formatPortID(data []byte) string {
	if len(data) < 2 || len(data) > MAX_STRING_LENGTH {
		return ""
	}
	subtype := data[0]
	value := data[1:]

	switch subtype {
	case 3:
		if len(value) == 6 {
			return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				value[0], value[1], value[2], value[3], value[4], value[5])
		}
	case 5, 7:
		return sanitizeString(value)
	}
	return sanitizeString(value)
}

func printLLDPInfo(info LLDPInfo) {
	fmt.Printf("Interface: %s\n", info.Interface)
	if info.SystemName != "" {
		fmt.Printf("  System Name: %s\n", info.SystemName)
	}
	if info.SystemDesc != "" {
		fmt.Printf("  System Desc: %s\n", info.SystemDesc)
	}
	if info.ChassisID != "" {
		fmt.Printf("  Chassis ID:  %s\n", info.ChassisID)
	}
	if info.PortID != "" {
		fmt.Printf("  Port ID:     %s\n", info.PortID)
	}
	if info.PortDesc != "" {
		fmt.Printf("  Port Desc:   %s\n", info.PortDesc)
	}
	fmt.Println()
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
