//go:build linux

package gomap

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
	"time"
)

// TCP flag constants
const (
	tcpFIN uint16 = 0x0001
	tcpSYN uint16 = 0x0002
	tcpRST uint16 = 0x0004
	tcpPSH uint16 = 0x0008
	tcpACK uint16 = 0x0010
	tcpURG uint16 = 0x0020
)

// scanPortRaw sends a TCP packet with the specified flags and interprets the response.
// Used for FIN, Xmas, and Null scans.
//
// Behavior (per RFC 793):
//   - Closed port: responds with RST
//   - Open port: no response (open|filtered)
//   - Filtered: ICMP unreachable or no response
func scanPortRaw(resultCh chan<- PortResult, hostname, service string, port int, laddr string, flags uint16, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}
	responseCh := make(chan rawResponse, 1)

	sport := uint16(randomPort(10000, 65535))
	go listenForResponse(laddr, hostname, uint16(port), sport, responseCh, timeout)

	// Small delay to let listener start
	time.Sleep(5 * time.Millisecond)

	err := sendTCPPacket(laddr, hostname, sport, uint16(port), flags)
	if err != nil {
		result.State = PortFiltered
		resultCh <- result
		return
	}

	select {
	case resp := <-responseCh:
		if resp.flags&tcpRST != 0 {
			// RST received = closed
			result.State = PortClosed
		} else {
			// Other response
			result.State = PortOpenFiltered
			result.Open = true
		}
	case <-time.After(timeout):
		// No response = open|filtered
		result.State = PortOpenFiltered
		result.Open = true
	}

	resultCh <- result
}

// scanPortACK sends a TCP ACK packet. Used for firewall rule mapping.
//
// Behavior:
//   - Unfiltered: RST received (regardless of open/closed)
//   - Filtered: no response or ICMP unreachable
func scanPortACK(resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}
	responseCh := make(chan rawResponse, 1)

	sport := uint16(randomPort(10000, 65535))
	go listenForResponse(laddr, hostname, uint16(port), sport, responseCh, timeout)

	time.Sleep(5 * time.Millisecond)

	err := sendTCPPacket(laddr, hostname, sport, uint16(port), tcpACK)
	if err != nil {
		result.State = PortFiltered
		resultCh <- result
		return
	}

	select {
	case resp := <-responseCh:
		if resp.flags&tcpRST != 0 {
			result.State = PortUnfiltered
		} else {
			result.State = PortFiltered
		}
	case <-time.After(timeout):
		result.State = PortFiltered
	}

	resultCh <- result
}

// scanPortWindow is like ACK scan but examines the TCP window size in RST responses.
//
// Behavior:
//   - Open: RST with non-zero window size
//   - Closed: RST with zero window size
//   - Filtered: no response
func scanPortWindow(resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}
	responseCh := make(chan rawResponse, 1)

	sport := uint16(randomPort(10000, 65535))
	go listenForResponse(laddr, hostname, uint16(port), sport, responseCh, timeout)

	time.Sleep(5 * time.Millisecond)

	err := sendTCPPacket(laddr, hostname, sport, uint16(port), tcpACK)
	if err != nil {
		result.State = PortFiltered
		resultCh <- result
		return
	}

	select {
	case resp := <-responseCh:
		if resp.flags&tcpRST != 0 {
			if resp.window > 0 {
				result.State = PortOpen
				result.Open = true
			} else {
				result.State = PortClosed
			}
		} else {
			result.State = PortFiltered
		}
	case <-time.After(timeout):
		result.State = PortFiltered
	}

	resultCh <- result
}

type rawResponse struct {
	flags  uint16
	window uint16
}

// listenForResponse listens for a TCP response from the target host on the
// specified source port.
func listenForResponse(laddr, raddr string, dport, sport uint16, ch chan<- rawResponse, timeout time.Duration) {
	listenAddr, err := net.ResolveIPAddr("ip4", laddr)
	if err != nil {
		return
	}

	conn, err := net.ListenIP("ip4:tcp", listenAddr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout + 100*time.Millisecond))

	for {
		buf := make([]byte, 1024)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if addr.String() != raddr || n < 20 {
			continue
		}

		// Parse TCP header
		srcPort := binary.BigEndian.Uint16(buf[0:2])
		dstPort := binary.BigEndian.Uint16(buf[2:4])

		if srcPort != dport || dstPort != sport {
			continue
		}

		// Data offset is top 4 bits of byte 12
		flags := binary.BigEndian.Uint16(buf[12:14]) & 0x003f
		window := binary.BigEndian.Uint16(buf[14:16])

		ch <- rawResponse{flags: flags, window: window}
		return
	}
}

// sendTCPPacket constructs and sends a raw TCP packet with the specified flags.
func sendTCPPacket(laddr, raddr string, sport, dport, flags uint16) error {
	op := []tcpOption{
		{
			Kind:   2,
			Length: 4,
			Data:   []byte{0x05, 0xb4},
		},
		{Kind: 0},
	}

	// Data offset (5 words + options) in upper 4 bits, flags in lower
	dataOffset := uint16(0x8000) // 8 = 32 bytes / 4 = data offset in 32-bit words
	flagField := dataOffset | flags

	tcpH := tcpHeader{
		SrcPort:       sport,
		DstPort:       dport,
		SeqNum:        rand.Uint32(),
		AckNum:        0,
		Flags:         flagField,
		Window:        8192,
		ChkSum:        0,
		UrgentPointer: 0,
	}

	conn, err := net.Dial("ip4:tcp", raddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Build packet for checksum
	buff := new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, tcpH)
	for i := range op {
		binary.Write(buff, binary.BigEndian, op[i].Kind)
		binary.Write(buff, binary.BigEndian, op[i].Length)
		binary.Write(buff, binary.BigEndian, op[i].Data)
	}
	binary.Write(buff, binary.BigEndian, [6]byte{})
	data := buff.Bytes()
	checkSum := tcpChecksum(data, ipToBytes(laddr), ipToBytes(raddr))
	tcpH.ChkSum = checkSum

	// Build final packet
	buff = new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, tcpH)
	for i := range op {
		binary.Write(buff, binary.BigEndian, op[i].Kind)
		binary.Write(buff, binary.BigEndian, op[i].Length)
		binary.Write(buff, binary.BigEndian, op[i].Data)
	}
	binary.Write(buff, binary.BigEndian, [6]byte{})

	_, err = conn.Write(buff.Bytes())
	return err
}
