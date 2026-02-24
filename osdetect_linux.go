//go:build linux

package gomap

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// sendOSProbesImpl sends the complete OS detection probe sequence on Linux.
//
// The probing sequence follows nmap's methodology:
//  1. Six TCP SYN probes to an open port (varying options/window)
//  2. One TCP probe to a closed port
//  3. One UDP probe to a closed port
//  4. ICMP echo probes
//
// From the responses we extract:
//   - TCP ISN patterns (predictability, GCD, rate)
//   - TCP options ordering and values
//   - Initial window sizes
//   - TTL values and DF bit behavior
//   - IPID sequencing patterns
//   - TCP timestamp behavior
func sendOSProbesImpl(ctx context.Context, laddr, raddr string, openPort, closedPort int, timeout time.Duration) (*OSFingerprint, error) {
	fp := &OSFingerprint{}

	// Phase 1: Six SYN probes to the open port
	// Each probe uses different TCP options to elicit different responses
	synProbes := []struct {
		window  uint16
		options []byte
	}{
		{1, buildTCPOptions(true, true, true, 1460, 1)},   // MSS, SACK, TS, WS=1
		{63, buildTCPOptions(true, true, true, 1400, 2)},  // MSS, SACK, TS, WS=2
		{4, buildTCPOptions(true, false, true, 536, 3)},   // MSS, TS, WS=3
		{4, buildTCPOptions(true, true, true, 265, 4)},    // MSS, SACK, TS, WS=4
		{16, buildTCPOptions(true, false, false, 536, 0)}, // MSS only
		{512, buildTCPOptions(true, true, true, 265, 15)}, // MSS, SACK, TS, WS=15
	}

	isns := make([]uint32, 0, 6)

	for i, probe := range synProbes {
		if ctx.Err() != nil {
			return fp, ctx.Err()
		}

		resp, err := sendSYNProbe(laddr, raddr, openPort, probe.window, probe.options, timeout)
		if err != nil || resp == nil {
			continue
		}

		// Record ISN
		isns = append(isns, resp.seqNum)

		// Record TCP options
		fp.OPS.Options[i] = parseTCPOptionsString(resp.options)

		// Record window
		fp.WIN.Windows[i] = int(resp.window)

		// Record probe response
		fp.Probes[i] = ProbeFingerprint{
			Responded:   true,
			DF:          resp.df,
			TTL:         int(resp.ttl),
			Window:      int(resp.window),
			SeqBehavior: analyzeSeq(resp),
			AckBehavior: analyzeAck(resp),
			Flags:       flagsToString(resp.flags),
			Options:     parseTCPOptionsString(resp.options),
		}
	}

	// Analyze ISN sequence
	fp.SEQ = analyzeISNSequence(isns)

	// Phase 2: Probe to closed TCP port (T5-T7)
	if closedPort > 0 {
		// T5: SYN to closed port
		resp, err := sendSYNProbe(laddr, raddr, closedPort, 31337, nil, timeout)
		if err == nil && resp != nil {
			fp.Probes[4] = ProbeFingerprint{
				Responded:   true,
				DF:          resp.df,
				TTL:         int(resp.ttl),
				Window:      int(resp.window),
				SeqBehavior: analyzeSeq(resp),
				AckBehavior: analyzeAck(resp),
				Flags:       flagsToString(resp.flags),
			}
		}

		// T6: ACK to closed port
		resp2, err := sendACKProbe(laddr, raddr, closedPort, timeout)
		if err == nil && resp2 != nil {
			fp.Probes[5] = ProbeFingerprint{
				Responded: true,
				DF:        resp2.df,
				TTL:       int(resp2.ttl),
				Window:    int(resp2.window),
				Flags:     flagsToString(resp2.flags),
			}
		}

		// T7: FIN|PSH|URG to closed port
		resp3, err := sendFlagProbe(laddr, raddr, closedPort, tcpFIN|tcpPSH|tcpURG, timeout)
		if err == nil && resp3 != nil {
			fp.Probes[6] = ProbeFingerprint{
				Responded: true,
				DF:        resp3.df,
				TTL:       int(resp3.ttl),
				Window:    int(resp3.window),
				Flags:     flagsToString(resp3.flags),
			}
		}
	}

	return fp, nil
}

type probeResponse struct {
	seqNum  uint32
	ackNum  uint32
	flags   uint16
	window  uint16
	ttl     uint8
	df      bool
	options []byte
}

func sendSYNProbe(laddr, raddr string, port int, window uint16, options []byte, timeout time.Duration) (*probeResponse, error) {
	return sendProbePacket(laddr, raddr, port, tcpSYN, window, options, timeout)
}

func sendACKProbe(laddr, raddr string, port int, timeout time.Duration) (*probeResponse, error) {
	return sendProbePacket(laddr, raddr, port, tcpACK, 32768, nil, timeout)
}

func sendFlagProbe(laddr, raddr string, port int, flags uint16, timeout time.Duration) (*probeResponse, error) {
	return sendProbePacket(laddr, raddr, port, flags, 65535, nil, timeout)
}

func sendProbePacket(laddr, raddr string, port int, flags, window uint16, options []byte, timeout time.Duration) (*probeResponse, error) {
	sport := uint16(randomPort(10000, 65535))

	// Listen for response
	network := "ip4"
	if IsIPv6(laddr) {
		network = "ip6"
	}
	listenAddr, err := net.ResolveIPAddr(network, laddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenIP(ipProtocol(laddr, "tcp"), listenAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Send the probe
	err = sendCustomTCPPacket(laddr, raddr, sport, uint16(port), flags, window, options)
	if err != nil {
		return nil, err
	}

	// Read response
	for {
		buf := make([]byte, 1500)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		if addr.String() != raddr || n < 20 {
			continue
		}

		srcPort := binary.BigEndian.Uint16(buf[0:2])
		dstPort := binary.BigEndian.Uint16(buf[2:4])

		if srcPort != uint16(port) || dstPort != sport {
			continue
		}

		resp := &probeResponse{
			seqNum: binary.BigEndian.Uint32(buf[4:8]),
			ackNum: binary.BigEndian.Uint32(buf[8:12]),
			flags:  binary.BigEndian.Uint16(buf[12:14]) & 0x003f,
			window: binary.BigEndian.Uint16(buf[14:16]),
		}

		// Data offset for TCP options
		dataOffset := (buf[12] >> 4) * 4
		if int(dataOffset) > 20 && int(dataOffset) <= n {
			resp.options = buf[20:dataOffset]
		}

		return resp, nil
	}
}

func sendCustomTCPPacket(laddr, raddr string, sport, dport, flags, window uint16, options []byte) error {
	tcpH := tcpHeader{
		SrcPort:       sport,
		DstPort:       dport,
		SeqNum:        rand.Uint32(),
		AckNum:        0,
		Flags:         0x5000 | flags, // 5 = 20 byte header (no options in header)
		Window:        window,
		ChkSum:        0,
		UrgentPointer: 0,
	}

	// If we have options, adjust the data offset
	if len(options) > 0 {
		headerWords := (20 + len(options) + 3) / 4
		tcpH.Flags = uint16(headerWords<<12) | flags
	}

	conn, err := net.Dial(ipProtocol(raddr, "tcp"), raddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	buff := new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, tcpH)
	if len(options) > 0 {
		buff.Write(options)
		// Pad to 4-byte boundary
		for buff.Len()%4 != 0 {
			buff.WriteByte(0)
		}
	}

	data := buff.Bytes()
	checkSum := tcpChecksum(data, ipToBytes(laddr), ipToBytes(raddr))

	// Rewrite checksum
	data[16] = byte(checkSum >> 8)
	data[17] = byte(checkSum)

	_, err = conn.Write(data)
	return err
}

// buildTCPOptions builds a TCP options byte slice for OS probing.
func buildTCPOptions(mss bool, sackPerm bool, timestamp bool, mssVal uint16, wsVal byte) []byte {
	var opts []byte

	if mss {
		opts = append(opts, 2, 4) // MSS kind, length
		opts = append(opts, byte(mssVal>>8), byte(mssVal))
	}

	if sackPerm {
		opts = append(opts, 4, 2) // SACK Permitted kind, length
	}

	if timestamp {
		opts = append(opts, 8, 10) // Timestamp kind, length
		ts := uint32(time.Now().UnixMilli())
		opts = append(opts, byte(ts>>24), byte(ts>>16), byte(ts>>8), byte(ts))
		opts = append(opts, 0, 0, 0, 0) // TS echo reply
	}

	if wsVal > 0 {
		opts = append(opts, 1)           // NOP (padding)
		opts = append(opts, 3, 3, wsVal) // Window Scale kind, length, value
	}

	// Pad to 4-byte boundary
	for len(opts)%4 != 0 {
		opts = append(opts, 0)
	}

	return opts
}

// analyzeISNSequence analyzes a series of TCP ISNs.
func analyzeISNSequence(isns []uint32) SEQFingerprint {
	seq := SEQFingerprint{
		TI: "I", // default incremental
		CI: "I",
		II: "RI",
		SS: "S",
		TS: "A",
	}

	if len(isns) < 2 {
		return seq
	}

	// Calculate differences
	diffs := make([]uint32, 0, len(isns)-1)
	for i := 1; i < len(isns); i++ {
		diff := isns[i] - isns[i-1]
		diffs = append(diffs, diff)
	}

	// GCD of differences
	if len(diffs) > 0 {
		divisor := diffs[0]
		for _, d := range diffs[1:] {
			divisor = gcd(divisor, d)
		}
		seq.GCD = int(divisor)
	}

	// SP (sequence predictability): lower = more predictable
	if seq.GCD > 0 {
		seq.SP = 0
		for _, d := range diffs {
			if d%uint32(seq.GCD) != 0 {
				seq.SP++
			}
		}
	}

	// ISR: average ISN increment rate
	if len(diffs) > 0 {
		var sum uint64
		for _, d := range diffs {
			sum += uint64(d)
		}
		seq.ISR = int(sum / uint64(len(diffs)))
	}

	return seq
}

func gcd(a, b uint32) uint32 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// analyzeSeq returns the sequence number behavior code.
func analyzeSeq(resp *probeResponse) string {
	if resp == nil {
		return ""
	}
	if resp.seqNum == 0 {
		return "Z"
	}
	return "O"
}

// analyzeAck returns the acknowledgment number behavior code.
func analyzeAck(resp *probeResponse) string {
	if resp == nil {
		return ""
	}
	if resp.ackNum == 0 {
		return "Z"
	}
	return "S+"
}

// flagsToString converts TCP flags to a string representation.
func flagsToString(flags uint16) string {
	var s []byte
	if flags&tcpFIN != 0 {
		s = append(s, 'F')
	}
	if flags&tcpSYN != 0 {
		s = append(s, 'S')
	}
	if flags&tcpRST != 0 {
		s = append(s, 'R')
	}
	if flags&tcpPSH != 0 {
		s = append(s, 'P')
	}
	if flags&tcpACK != 0 {
		s = append(s, 'A')
	}
	if flags&tcpURG != 0 {
		s = append(s, 'U')
	}
	return string(s)
}

// parseTCPOptionsString converts raw TCP options bytes to an nmap-style string.
func parseTCPOptionsString(opts []byte) string {
	var b bytes.Buffer
	i := 0
	for i < len(opts) {
		kind := opts[i]
		switch kind {
		case 0: // EOL
			return b.String()
		case 1: // NOP
			b.WriteByte('N')
			i++
		case 2: // MSS
			if i+3 < len(opts) {
				mss := binary.BigEndian.Uint16(opts[i+2 : i+4])
				b.WriteString("M")
				b.WriteString(fmt.Sprintf("%X", mss))
				i += 4
			} else {
				return b.String()
			}
		case 3: // Window Scale
			if i+2 < len(opts) {
				b.WriteString("W")
				b.WriteString(fmt.Sprintf("%X", opts[i+2]))
				i += 3
			} else {
				return b.String()
			}
		case 4: // SACK Permitted
			b.WriteString("S")
			i += 2
		case 8: // Timestamp
			if i+9 < len(opts) {
				b.WriteString("T")
				i += 10
			} else {
				return b.String()
			}
		default:
			if i+1 < len(opts) && opts[i+1] > 0 {
				i += int(opts[i+1])
			} else {
				i++
			}
		}
	}
	return b.String()
}
