//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	bootRequest = 1
	bootReply   = 2
	htypeEther  = 1
	hlenEther   = 6

	dhcpMagicCookie = 0x63825363

	// DHCP options
	optSubnetMask    = 1
	optRouter        = 3
	optDNSServer     = 6
	optBroadcastAddr = 28
	optRequestedIP   = 50
	optMessageType   = 53
	optServerID      = 54
	optParamReqList  = 55
	optMaxMsgSize    = 57
	optClientID      = 61
	optClasslessRT   = 121
	optEnd           = 255
	optPad           = 0

	// DHCP message types
	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpAck      = 5
	dhcpNak      = 6
)

// Netlink receive timeout to avoid indefinite hangs.
const nlRecvTimeout = 2 * time.Second

type lease struct {
	ifIndex int
	ifName  string
	mac     [6]byte
	xid     uint32

	serverID  netip.Addr
	addr      netip.Addr
	mask      netip.Addr
	broadcast netip.Addr
	gateway   netip.Addr
	dns       []netip.Addr
	routes    []route
}

type route struct {
	dst netip.Prefix
	gw  netip.Addr
}

var nlSeq uint32

func nlNextSeq() uint32 { return atomic.AddUint32(&nlSeq, 1) }

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: minidhcp [interface]")
		fmt.Fprintln(os.Stderr, "Minimal DHCPv4 client")
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	ifName := flag.Arg(0)

	atomic.StoreUint32(&nlSeq,
		randUint32()^uint32(os.Getpid())^uint32(time.Now().UnixNano()))

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Error: must run as root or with CAP_NET_RAW+CAP_NET_ADMIN")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	l, err := dhcpAcquire(ctx, ifName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := applyLease(l); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	gw := "-"
	if l.gateway.IsValid() {
		gw = l.gateway.String()
	}

	fmt.Printf("OK %s %s/%d gw=%s dns=%d routes=%d\n",
		l.ifName,
		l.addr,
		maskToPrefixLen(l.mask),
		gw,
		len(l.dns),
		len(l.routes),
	)
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

/* ================= DHCP acquisition (raw socket) ================= */

func dhcpAcquire(ctx context.Context, ifName string) (*lease, error) {
	ifi, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("Interface: %w", err)
	}
	if ifi.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("Interface %s is down", ifName)
	}
	if len(ifi.HardwareAddr) != 6 {
		return nil, fmt.Errorf("Interface %s: not ethernet", ifName)
	}

	var mac [6]byte
	copy(mac[:], ifi.HardwareAddr[:6])

	l := &lease{
		ifIndex: ifi.Index,
		ifName:  ifi.Name,
		mac:     mac,
		xid:     randUint32(),
	}

	logf("Interface %s: MAC=%s MTU=%d", ifi.Name, ifi.HardwareAddr, ifi.MTU)
	logf("Transaction ID: 0x%08x", l.xid)

	// L3 packet socket (no Ethernet header), protocol IPv4.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(0x0800)))
	if err != nil {
		return nil, fmt.Errorf("Socket: %w", err)
	}
	// Best-effort: ignore outgoing frames on this socket (hardening).
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, packetIgnoreOutgoing, 1)
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(0x0800),
		Ifindex:  ifi.Index,
	}); err != nil {
		return nil, fmt.Errorf("Bind: %w", err)
	}

	bcastAddr := &unix.SockaddrLinklayer{
		Protocol: htons(0x0800),
		Ifindex:  ifi.Index,
		Halen:    6,
	}
	copy(bcastAddr.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	const tries = 5
	const timeout = 10 * time.Second

	// DISCOVER -> OFFER
	var offer *dhcpMsg
	for i := range tries {
		logf("Sending DISCOVER (%d/%d)", i+1, tries)

		pkt := buildPacket(l, dhcpDiscover)
		if err := unix.Sendto(fd, pkt, 0, bcastAddr); err != nil {
			return nil, fmt.Errorf("Send: %w", err)
		}

		offer, err = recvDHCP(ctx, fd, l, timeout, dhcpOffer, 0)
		if err == nil {
			logf("Received OFFER")
			break
		}
		if i == tries-1 {
			return nil, fmt.Errorf("No OFFER: %w", err)
		}
		time.Sleep(time.Second)
	}

	if err := parseLease(l, offer, true); err != nil {
		return nil, err
	}
	logf("Offered IP=%s server=%s", l.addr, l.serverID)

	// REQUEST -> ACK/NAK
	var ack *dhcpMsg
	for i := range tries {
		logf("Sending REQUEST (%d/%d)", i+1, tries)

		pkt := buildPacket(l, dhcpRequest)
		if err := unix.Sendto(fd, pkt, 0, bcastAddr); err != nil {
			return nil, fmt.Errorf("Send: %w", err)
		}

		ack, err = recvDHCP(ctx, fd, l, timeout, dhcpAck, dhcpNak)
		if err != nil {
			if i == tries-1 {
				return nil, fmt.Errorf("No ACK: %w", err)
			}
			time.Sleep(time.Second)
			continue
		}

		mt := ack.opt(optMessageType)
		if len(mt) == 1 && mt[0] == dhcpNak {
			return nil, errors.New("Server sent NAK")
		}
		if len(mt) == 1 && mt[0] == dhcpAck {
			logf("Received ACK")
			break
		}
	}

	if err := parseLease(l, ack, true); err != nil {
		return nil, err
	}
	return l, nil
}

func recvDHCP(ctx context.Context, fd int, l *lease, timeout time.Duration, want1, want2 byte) (*dhcpMsg, error) {
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO,
		&unix.Timeval{Sec: int64(timeout.Seconds())})

	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return nil, errors.New("Timeout")
			}
			return nil, err
		}

		// IPv4 sanity checks
		if n < 20 {
			continue
		}
		ver := buf[0] >> 4
		ihl := int(buf[0]&0x0f) * 4
		if ver != 4 || ihl < 20 || n < ihl+8 {
			continue
		}
		totalLen := int(binary.BigEndian.Uint16(buf[2:4]))
		if totalLen < ihl+8 || totalLen > n {
			continue
		}
		// Header checksum integrity.
		if !ipv4HeaderChecksumOK(buf[:ihl]) {
			continue
		}
		// Drop packets with 0.0.0.0 source.
		srcIP := buf[12:16]
		if srcIP[0] == 0 && srcIP[1] == 0 && srcIP[2] == 0 && srcIP[3] == 0 {
			continue
		}
		frag := binary.BigEndian.Uint16(buf[6:8])
		if (frag&0x1fff) != 0 || (frag&0x2000) != 0 {
			continue
		}
		if buf[9] != 17 {
			continue
		}

		udpStart := ihl
		udpLen := int(binary.BigEndian.Uint16(buf[udpStart+4 : udpStart+6]))
		if udpLen < 8 || udpStart+udpLen > totalLen {
			continue
		}
		srcPort := binary.BigEndian.Uint16(buf[udpStart : udpStart+2])
		dstPort := binary.BigEndian.Uint16(buf[udpStart+2 : udpStart+4])
		if srcPort != 67 || dstPort != 68 {
			continue
		}

		// UDP checksum validation (checksum field at offset 6)
		udpCsum := binary.BigEndian.Uint16(buf[udpStart+6 : udpStart+8])
		if udpCsum != 0 {
			// Zero means checksum not computed (valid for IPv4/UDP)
			srcIP := buf[12:16]
			dstIP := buf[16:20]
			if !udpChecksumOK(srcIP, dstIP, buf[udpStart:udpStart+udpLen]) {
				continue
			}
		}

		dhcpData := buf[udpStart+8 : udpStart+udpLen]
		m, ok := parseDHCP(dhcpData, l)
		if !ok {
			continue
		}

		mt := m.opt(optMessageType)
		if len(mt) != 1 {
			continue
		}
		if mt[0] == want1 || (want2 != 0 && mt[0] == want2) {
			return m, nil
		}
	}
}

func buildPacket(l *lease, msgType byte) []byte {
	dhcp := buildDHCP(l, msgType)
	udp := buildUDP(68, 67, dhcp)
	src := [4]byte{0, 0, 0, 0}
	dst := [4]byte{255, 255, 255, 255}
	// Always broadcast (matching udhcpc behavior)
	// RFC 2131 allows both broadcast and unicast, but broadcasting is more compatible
	return buildIPv4(src, dst, 17, udp)
}

func buildIPv4(src, dst [4]byte, proto byte, payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], uint16(20+len(payload)))
	h[8] = 64
	h[9] = proto
	copy(h[12:16], src[:])
	copy(h[16:20], dst[:])

	// Header checksum
	sum := uint32(0)
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(h[10:12], uint16(^sum))

	return append(h, payload...)
}

func buildUDP(sport, dport uint16, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint16(h[4:6], uint16(8+len(payload)))
	// UDP checksum optional for IPv4; leave 0.
	return append(h, payload...)
}

func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }

const packetIgnoreOutgoing = 23

/* ================= DHCP wire protocol ================= */

type dhcpMsg struct {
	yiaddr [4]byte
	opts   map[byte][]byte
}

func (m *dhcpMsg) opt(code byte) []byte { return m.opts[code] }

func buildDHCP(l *lease, msgType byte) []byte {
	h := make([]byte, 236)
	h[0] = bootRequest
	h[1] = htypeEther
	h[2] = hlenEther
	binary.BigEndian.PutUint32(h[4:8], l.xid)
	binary.BigEndian.PutUint16(h[10:12], 0x8000)
	copy(h[28:34], l.mac[:])

	out := make([]byte, 0, 320)
	out = append(out, h...)

	var cookie [4]byte
	binary.BigEndian.PutUint32(cookie[:], dhcpMagicCookie)
	out = append(out, cookie[:]...)

	out = appendOpt(out, optMessageType, []byte{msgType})

	// client-id: ethernet + MAC
	cid := make([]byte, 1+6)
	cid[0] = 1
	copy(cid[1:], l.mac[:])
	out = appendOpt(out, optClientID, cid)

	// max msg size: 576 (minimum IPv4 reassembly size)
	var mms [2]byte
	binary.BigEndian.PutUint16(mms[:], 576)
	out = appendOpt(out, optMaxMsgSize, mms[:])

	out = appendOpt(out, optParamReqList, []byte{
		optSubnetMask,
		optBroadcastAddr,
		optRouter,
		optDNSServer,
		optClasslessRT,
	})

	if msgType == dhcpRequest {
		if l.serverID.IsValid() && l.serverID.Is4() {
			out = appendOpt(out, optServerID, l.serverID.AsSlice())
		}
		if l.addr.IsValid() && l.addr.Is4() {
			out = appendOpt(out, optRequestedIP, l.addr.AsSlice())
		}
	}

	out = append(out, optEnd)
	for len(out) < 300 {
		out = append(out, 0)
	}
	return out
}

func appendOpt(b []byte, code byte, val []byte) []byte {
	if code == optPad || code == optEnd {
		return append(b, code)
	}
	if len(val) > 255 {
		val = val[:255]
	}
	b = append(b, code, byte(len(val)))
	return append(b, val...)
}

func parseDHCP(pkt []byte, l *lease) (*dhcpMsg, bool) {
	if len(pkt) < 240 {
		return nil, false
	}

	// BOOTP/DHCP header sanity: Ethernet + 6-byte MAC only.
	if pkt[1] != htypeEther {
		return nil, false
	}
	if pkt[2] != hlenEther {
		return nil, false
	}

	if pkt[0] != bootReply {
		return nil, false
	}
	if binary.BigEndian.Uint32(pkt[4:8]) != l.xid {
		return nil, false
	}
	if !equal6(pkt[28:34], l.mac[:]) {
		return nil, false
	}
	if binary.BigEndian.Uint32(pkt[236:240]) != dhcpMagicCookie {
		return nil, false
	}

	var m dhcpMsg
	copy(m.yiaddr[:], pkt[16:20])
	opts, ok := parseOptions(pkt[240:])
	if !ok {
		return nil, false
	}
	m.opts = opts
	return &m, true
}

func parseOptions(b []byte) (map[byte][]byte, bool) {
	out := make(map[byte][]byte)
	for i := 0; i < len(b); {
		code := b[i]
		i++
		switch code {
		case optPad:
			continue
		case optEnd:
			return out, true
		default:
			if i >= len(b) {
				return nil, false
			}
			length := int(b[i])
			i++
			if i+length > len(b) {
				return nil, false
			}
			v := b[i : i+length]
			if prev, exists := out[code]; exists {
				// Reject conflicting duplicates for critical options.
				if (code == optMessageType || code == optServerID) && !bytes.Equal(prev, v) {
					return nil, false
				}
			}
			out[code] = v
			i += length
		}
	}
	return out, true
}

func parseLease(l *lease, m *dhcpMsg, requireSID bool) error {
	ip, ok := netip.AddrFromSlice(m.yiaddr[:])
	if !ok || !ip.Is4() {
		return errors.New("Invalid IP address")
	}
	l.addr = ip

	var seenSID netip.Addr
	if v := m.opt(optServerID); len(v) == 4 {
		if a, ok := netip.AddrFromSlice(v); ok && a.Is4() {
			seenSID = a
		}
	}
	if seenSID.IsValid() {
		if l.serverID.IsValid() && l.serverID != seenSID {
			return errors.New("Server ID mismatch between messages")
		}
		l.serverID = seenSID
	}
	if requireSID && !l.serverID.IsValid() {
		return errors.New("Missing server ID")
	}

	if v := m.opt(optSubnetMask); len(v) == 4 {
		if a, ok := netip.AddrFromSlice(v); ok && a.Is4() {
			l.mask = a
		}
	}
	if !l.mask.IsValid() {
		return errors.New("Missing subnet mask")
	}

	if v := m.opt(optBroadcastAddr); len(v) == 4 {
		if a, ok := netip.AddrFromSlice(v); ok && a.Is4() {
			l.broadcast = a
		}
	}

	if v := m.opt(optRouter); len(v) >= 4 {
		if a, ok := netip.AddrFromSlice(v[:4]); ok && a.Is4() {
			l.gateway = a
		}
	}

	l.dns = l.dns[:0]
	if v := m.opt(optDNSServer); len(v) >= 4 && len(v)%4 == 0 {
		for i := 0; i < len(v); i += 4 {
			if a, ok := netip.AddrFromSlice(v[i : i+4]); ok && a.Is4() {
				l.dns = append(l.dns, a)
			}
		}
	}

	l.routes = l.routes[:0]
	if v := m.opt(optClasslessRT); len(v) > 0 {
		rts, err := parseClasslessRoutes(v)
		if err != nil {
			return err
		}
		l.routes = rts
	} else if l.gateway.IsValid() {
		l.routes = []route{{dst: netip.MustParsePrefix("0.0.0.0/0"), gw: l.gateway}}
	}

	return nil
}

func parseClasslessRoutes(b []byte) ([]route, error) {
	var out []route
	i := 0
	for i < len(b) {
		width := int(b[i])
		i++
		if width > 32 {
			return nil, errors.New("Invalid route prefix length")
		}
		nbytes := (width + 7) / 8
		if i+nbytes+4 > len(b) {
			return nil, errors.New("Truncated route option")
		}

		var dst [4]byte
		copy(dst[:nbytes], b[i:i+nbytes])
		i += nbytes

		gwBytes := b[i : i+4]
		i += 4

		dstAddr, ok := netip.AddrFromSlice(dst[:])
		if !ok {
			return nil, errors.New("Invalid destination address")
		}
		gw, ok := netip.AddrFromSlice(gwBytes)
		if !ok {
			return nil, errors.New("Invalid gateway address")
		}

		out = append(out, route{
			dst: netip.PrefixFrom(dstAddr, width),
			gw:  gw,
		})
	}
	return out, nil
}

/* ================= Apply lease (netlink flush + add) ================= */

func applyLease(l *lease) error {
	pfx := maskToPrefixLen(l.mask)
	if pfx <= 0 || pfx > 32 {
		return errors.New("Invalid subnet mask")
	}

	logf("Applying: IP=%s/%d", l.addr, pfx)

	// Set/update address first (netlink NLM_F_REPLACE handles atomic update).
	// This ensures we never lose connectivity - old IP stays until new one is active.
	addrStr := fmt.Sprintf("%s/%d", l.addr.String(), pfx)
	if l.broadcast.IsValid() {
		logf("Setting address: %s broadcast %s", addrStr, l.broadcast.String())
	} else {
		logf("Setting address: %s", addrStr)
	}
	if err := nlAddIPv4Addr(l.ifIndex, l.addr, pfx, l.broadcast); err != nil {
		return fmt.Errorf("Add address: %w", err)
	}

	// Flush routes only after new IP is active (routes need valid source address).
	logf("Flushing existing IPv4 routes (main table) via dev")
	if err := nlFlushIPv4Routes(l.ifIndex); err != nil {
		logf("Warning: flush routes failed: %v", err)
	}

	// Sort routes by prefix length (most specific first).
	// This ensures host routes (/32) are added before default routes (/0).
	// Required for gateways that aren't in the same subnet.
	type sortableRoute struct {
		dst netip.Prefix
		gw  netip.Addr
	}
	sortedRoutes := make([]sortableRoute, len(l.routes))
	for i, r := range l.routes {
		sortedRoutes[i] = sortableRoute{dst: r.dst, gw: r.gw}
	}
	// Simple insertion sort by prefix bits (descending)
	for i := 1; i < len(sortedRoutes); i++ {
		for j := i; j > 0 && sortedRoutes[j].dst.Bits() > sortedRoutes[j-1].dst.Bits(); j-- {
			sortedRoutes[j], sortedRoutes[j-1] = sortedRoutes[j-1], sortedRoutes[j]
		}
	}

	for _, r := range sortedRoutes {
		logf("Adding route: %s via %s", r.dst, r.gw)
		if err := nlAddIPv4Route(l.ifIndex, r.dst, r.gw); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("add route %s: %w", r.dst, err)
		}
	}

	if len(l.dns) > 0 {
		var dnsStr strings.Builder
		for i, d := range l.dns {
			if i > 0 {
				dnsStr.WriteByte(' ')
			}
			dnsStr.WriteString(d.String())
		}
		logf("Writing DNS: %s", dnsStr.String())
		_ = writeResolv(l.dns)
	}

	return nil
}

/* ================= Netlink helpers ================= */

func nlOpen() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}

	// Hardening: avoid indefinite hangs on netlink receive.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{
		Sec:  int64(nlRecvTimeout / time.Second),
		Usec: int64((nlRecvTimeout % time.Second) / time.Microsecond),
	})

	return fd, nil
}

func nlmsgAlign(n int) int { return (n + 3) &^ 3 }

func nlSend(fd int, typ uint16, flags uint16, seq uint32, payload []byte) error {
	hdr := unix.NlMsghdr{
		Len:   uint32(unix.NLMSG_HDRLEN + len(payload)),
		Type:  typ,
		Flags: flags,
		Seq:   seq,
		Pid:   0, // to kernel
	}
	pkt := make([]byte, 0, int(hdr.Len))
	pkt = append(pkt, unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), unix.NLMSG_HDRLEN)...)
	pkt = append(pkt, payload...)
	return unix.Sendto(fd, pkt, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

// For NEW/DEL operations with NLM_F_ACK: kernel replies with NLMSG_ERROR(error=0) only.
func nlRecvAck(fd int, seq uint32) error {
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return errors.New("Netlink timeout")
			}
			return err
		}
		for off := 0; off+unix.NLMSG_HDRLEN <= n; {
			h := *(*unix.NlMsghdr)(unsafe.Pointer(&buf[off]))
			if h.Len < uint32(unix.NLMSG_HDRLEN) {
				return errors.New("Bad netlink len")
			}
			end := off + int(h.Len)
			if end > n {
				return errors.New("Truncated netlink msg")
			}
			data := buf[off+unix.NLMSG_HDRLEN : end]

			if h.Seq != seq {
				off = nlmsgAlign(end)
				continue
			}
			if h.Type != unix.NLMSG_ERROR {
				off = nlmsgAlign(end)
				continue
			}
			if len(data) < unix.SizeofNlMsgerr {
				return errors.New("Short NLMSG_ERROR")
			}
			e := *(*unix.NlMsgerr)(unsafe.Pointer(&data[0]))
			if e.Error == 0 {
				return nil
			}
			return unix.Errno(-e.Error)
		}
	}
}

// For DUMP operations: receive messages until NLMSG_DONE.
func nlRecvDump(fd int, seq uint32, cb func(h unix.NlMsghdr, data []byte) error) error {
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return errors.New("Netlink timeout")
			}
			return err
		}
		for off := 0; off+unix.NLMSG_HDRLEN <= n; {
			h := *(*unix.NlMsghdr)(unsafe.Pointer(&buf[off]))
			if h.Len < uint32(unix.NLMSG_HDRLEN) {
				return errors.New("Bad netlink len")
			}
			end := off + int(h.Len)
			if end > n {
				return errors.New("Truncated netlink msg")
			}
			data := buf[off+unix.NLMSG_HDRLEN : end]

			if h.Seq != seq {
				off = nlmsgAlign(end)
				continue
			}

			switch h.Type {
			case unix.NLMSG_DONE:
				return nil
			case unix.NLMSG_ERROR:
				if len(data) < unix.SizeofNlMsgerr {
					return errors.New("Short NLMSG_ERROR")
				}
				e := *(*unix.NlMsgerr)(unsafe.Pointer(&data[0]))
				if e.Error == 0 {
					off = nlmsgAlign(end)
					continue
				}
				return unix.Errno(-e.Error)
			default:
				if err := cb(h, data); err != nil {
					return err
				}
			}
			off = nlmsgAlign(end)
		}
	}
}

func parseAttrs(b []byte) map[uint16][]byte {
	out := make(map[uint16][]byte)
	for len(b) >= unix.NLA_HDRLEN {
		l := int(binary.LittleEndian.Uint16(b[0:2])) // nla_len
		typ := binary.LittleEndian.Uint16(b[2:4])    // nla_type
		if l < unix.NLA_HDRLEN || l > len(b) {
			return out
		}
		v := make([]byte, l-unix.NLA_HDRLEN)
		copy(v, b[unix.NLA_HDRLEN:l])
		out[typ] = v
		b = b[nlmsgAlign(l):]
	}
	return out
}

func addAttr(b []byte, typ uint16, v []byte) []byte {
	l := unix.NLA_HDRLEN + len(v)
	pad := nlmsgAlign(l) - l

	var hdr [unix.NLA_HDRLEN]byte
	binary.LittleEndian.PutUint16(hdr[0:2], uint16(l)) // nla_len
	binary.LittleEndian.PutUint16(hdr[2:4], typ)       // nla_type

	b = append(b, hdr[:]...)
	b = append(b, v...)
	if pad > 0 {
		var zero [3]byte
		b = append(b, zero[:pad]...)
	}
	return b
}

func addAttrU32(b []byte, typ uint16, v uint32) []byte {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	return addAttr(b, typ, tmp[:])
}

func nlAddIPv4Addr(ifIndex int, addr netip.Addr, prefixLen int, broadcast netip.Addr) error {
	if !addr.Is4() {
		return errors.New("Address not IPv4")
	}

	fd, err := nlOpen()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	seq := nlNextSeq()

	msg := unix.IfAddrmsg{
		Family:    unix.AF_INET,
		Prefixlen: uint8(prefixLen),
		Index:     uint32(ifIndex),
		Scope:     unix.RT_SCOPE_UNIVERSE,
	}
	payload := make([]byte, 0, 128)
	payload = append(payload, unsafe.Slice((*byte)(unsafe.Pointer(&msg)), unix.SizeofIfAddrmsg)...)

	a4 := addr.As4()
	payload = addAttr(payload, unix.IFA_LOCAL, a4[:])
	payload = addAttr(payload, unix.IFA_ADDRESS, a4[:])
	if broadcast.IsValid() && broadcast.Is4() {
		b4 := broadcast.As4()
		payload = addAttr(payload, unix.IFA_BROADCAST, b4[:])
	}

	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE)
	if err := nlSend(fd, unix.RTM_NEWADDR, flags, seq, payload); err != nil {
		return err
	}
	return nlRecvAck(fd, seq)
}

func nlFlushIPv4Routes(ifIndex int) error {
	fd, err := nlOpen()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	seq := nlNextSeq()

	var rtm unix.RtMsg
	rtm.Family = unix.AF_INET
	payload := unsafe.Slice((*byte)(unsafe.Pointer(&rtm)), unix.SizeofRtMsg)

	if err := nlSend(fd, unix.RTM_GETROUTE, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, seq, payload); err != nil {
		return err
	}

	type delRoute struct {
		dstBits  uint8
		dst      [4]byte
		gw       [4]byte
		protocol uint8
		hasDst   bool
		hasGw    bool
	}
	var dels []delRoute

	if err := nlRecvDump(fd, seq, func(h unix.NlMsghdr, data []byte) error {
		if len(data) < unix.SizeofRtMsg {
			return nil
		}
		m := *(*unix.RtMsg)(unsafe.Pointer(&data[0]))
		if m.Family != unix.AF_INET {
			return nil
		}

		attrs := parseAttrs(data[unix.SizeofRtMsg:])

		// Determine table: either m.Table, or attribute RTA_TABLE.
		table := m.Table
		if table == 0 {
			if tb := attrs[unix.RTA_TABLE]; len(tb) >= 1 {
				table = tb[0]
			}
		}
		if table != unix.RT_TABLE_MAIN {
			return nil
		}

		oifb := attrs[unix.RTA_OIF]
		if len(oifb) != 4 {
			return nil
		}
		oif := int(binary.LittleEndian.Uint32(oifb))
		if oif != ifIndex {
			return nil
		}

		// Skip kernel-managed routes (proto kernel): the kernel owns these
		// and will recreate them automatically when the address is set.
		if m.Protocol == unix.RTPROT_KERNEL {
			return nil
		}

		var dr delRoute
		dr.dstBits = m.Dst_len
		dr.protocol = m.Protocol

		if d := attrs[unix.RTA_DST]; len(d) == 4 {
			copy(dr.dst[:], d)
			dr.hasDst = true
		}
		if g := attrs[unix.RTA_GATEWAY]; len(g) == 4 {
			copy(dr.gw[:], g)
			dr.hasGw = true
		}

		dels = append(dels, dr)
		return nil
	}); err != nil {
		return err
	}

	for _, dr := range dels {
		if err := nlDelIPv4Route(ifIndex, dr); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
			return err
		}
	}
	return nil
}

func nlDelIPv4Route(ifIndex int, dr struct {
	dstBits  uint8
	dst      [4]byte
	gw       [4]byte
	protocol uint8
	hasDst   bool
	hasGw    bool
}) error {
	fd, err := nlOpen()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	seq := nlNextSeq()

	msg := unix.RtMsg{
		Family:   unix.AF_INET,
		Dst_len:  dr.dstBits,
		Table:    unix.RT_TABLE_MAIN,
		Type:     unix.RTN_UNICAST,
		Protocol: dr.protocol,
	}
	payload := make([]byte, 0, 128)
	payload = append(payload, unsafe.Slice((*byte)(unsafe.Pointer(&msg)), unix.SizeofRtMsg)...)

	if dr.dstBits != 0 && dr.hasDst {
		payload = addAttr(payload, unix.RTA_DST, dr.dst[:])
	}
	if dr.hasGw {
		payload = addAttr(payload, unix.RTA_GATEWAY, dr.gw[:])
	}
	payload = addAttrU32(payload, unix.RTA_OIF, uint32(ifIndex))

	if err := nlSend(fd, unix.RTM_DELROUTE, unix.NLM_F_REQUEST|unix.NLM_F_ACK, seq, payload); err != nil {
		return err
	}
	return nlRecvAck(fd, seq)
}

func nlAddIPv4Route(ifIndex int, dst netip.Prefix, gw netip.Addr) error {
	if !gw.Is4() || !dst.Addr().Is4() {
		return errors.New("Route not IPv4")
	}

	fd, err := nlOpen()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	seq := nlNextSeq()

	// A zero gateway means "on-link" (directly reachable via the interface).
	// Such routes must use RT_SCOPE_LINK and must not include RTA_GATEWAY,
	// otherwise the kernel rejects them with ENETUNREACH.
	scope := uint8(unix.RT_SCOPE_UNIVERSE)
	if gw == (netip.AddrFrom4([4]byte{})) {
		scope = unix.RT_SCOPE_LINK
	}

	msg := unix.RtMsg{
		Family:   unix.AF_INET,
		Dst_len:  uint8(dst.Bits()),
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_BOOT,
		Scope:    scope,
		Type:     unix.RTN_UNICAST,
	}
	payload := make([]byte, 0, 128)
	payload = append(payload, unsafe.Slice((*byte)(unsafe.Pointer(&msg)), unix.SizeofRtMsg)...)

	if dst.Bits() != 0 {
		d4 := dst.Addr().As4()
		payload = addAttr(payload, unix.RTA_DST, d4[:])
	}
	if scope == unix.RT_SCOPE_UNIVERSE {
		g4 := gw.As4()
		payload = addAttr(payload, unix.RTA_GATEWAY, g4[:])
	}
	payload = addAttrU32(payload, unix.RTA_OIF, uint32(ifIndex))

	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE)
	if err := nlSend(fd, unix.RTM_NEWROUTE, flags, seq, payload); err != nil {
		return err
	}
	return nlRecvAck(fd, seq)
}

/* ================= resolv.conf ================= */

func writeResolv(dns []netip.Addr) error {
	const path = "/etc/resolv.conf"

	target := path

	fi, err := os.Lstat(path)
	if err != nil {
		// If it doesn't exist, create/write /etc/resolv.conf directly.
		// Any other error (permission, etc.) is returned.
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if fi.Mode()&os.ModeSymlink != 0 {
		// If it's a symlink, write to the symlink destination (even if it doesn't exist yet).
		link, err := os.Readlink(path)
		if err != nil {
			return err
		}
		if filepath.IsAbs(link) {
			target = link
		} else {
			// Relative links are relative to the directory containing the symlink.
			target = filepath.Clean(filepath.Join(filepath.Dir(path), link))
		}
	}

	var b strings.Builder
	b.WriteString("# Generated by minidhcp\n")
	for _, a := range dns {
		if a.Is4() {
			b.WriteString("nameserver ")
			b.WriteString(a.String())
			b.WriteByte('\n')
		}
	}

	dir := filepath.Dir(target)
	base := filepath.Base(target)
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.WriteString(b.String()); err != nil {
		_ = tmp.Close()
		return err
	}
	_ = tmp.Chmod(0644)
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, target)
}

func ipv4HeaderChecksumOK(h []byte) bool {
	if len(h) < 20 {
		return false
	}
	sum := uint32(0)
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum) == 0xffff
}

func udpChecksumOK(srcIP, dstIP, udpPacket []byte) bool {
	if len(srcIP) != 4 || len(dstIP) != 4 || len(udpPacket) < 8 {
		return false
	}

	// UDP pseudo-header: src IP, dst IP, zero, protocol (17), UDP length
	udpLen := len(udpPacket)
	sum := uint32(0)

	// Add pseudo-header
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	sum += uint32(17)     // protocol
	sum += uint32(udpLen) // UDP length

	// Add UDP packet (with checksum field)
	for i := 0; i+1 < len(udpPacket); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpPacket[i : i+2]))
	}
	// Handle odd length
	if len(udpPacket)%2 == 1 {
		sum += uint32(udpPacket[len(udpPacket)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum) == 0xffff
}

/* ================= Utilities ================= */

func randUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint32(b[:])
	}
	v := uint64(time.Now().UnixNano()) ^ uint64(os.Getpid())<<32
	return uint32(v) ^ uint32(v>>32)
}

func equal6(a, b []byte) bool {
	return len(a) >= 6 && len(b) >= 6 && bytes.Equal(a[:6], b[:6])
}

func maskToPrefixLen(mask netip.Addr) int {
	if !mask.IsValid() || !mask.Is4() {
		return 0
	}
	m := mask.As4()
	ones := 0
	seenZero := false
	for i := range 32 {
		bit := (m[i/8] >> (7 - uint(i%8))) & 1
		if bit == 1 {
			if seenZero {
				return 0
			}
			ones++
		} else {
			seenZero = true
		}
	}
	return ones
}

func isIPv4Broadcast(b []byte) bool {
	return len(b) == 4 && binary.BigEndian.Uint32(b) == 0xffffffff
}
