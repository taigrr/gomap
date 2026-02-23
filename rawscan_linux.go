//go:build linux

package gomap

import (
	"bytes"
	"context"
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
func scanPortRaw(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, laddr string, flags uint16, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}

	if ctx.Err() != nil {
		result.State = PortFiltered
		resultCh <- result
		return
	}

	responseCh := make(chan rawResponse, 1)
	sport := uint16(randomPort(10000, 65535))
	go listenForResponse(laddr, hostname, uint16(port), sport, responseCh, timeout)
	time.Sleep(5 * time.Millisecond)

	err := sendTCPPacket(laddr, hostname, sport, uint16(port), flags)
	if err != nil {
		result.State = PortFiltered
		resultCh <- result
		return
	}

	select {
	case <-ctx.Done():
		result.setStateReason(PortFiltered, "no-response")
	case resp := <-responseCh:
		if resp.flags&tcpRST != 0 {
			result.setStateReason(PortClosed, "reset")
		} else {
			result.setStateReason(PortOpenFiltered, "no-response")
		}
	case <-time.After(timeout):
		result.setStateReason(PortOpenFiltered, "no-response")
	}

	resultCh <- result
}

// scanPortACK sends a TCP ACK packet for firewall rule mapping.
func scanPortACK(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}

	if ctx.Err() != nil {
		result.State = PortFiltered
		resultCh <- result
		return
	}

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
	case <-ctx.Done():
		result.setStateReason(PortFiltered, "no-response")
	case resp := <-responseCh:
		if resp.flags&tcpRST != 0 {
			result.setStateReason(PortUnfiltered, "reset")
		} else {
			result.setStateReason(PortFiltered, "no-response")
		}
	case <-time.After(timeout):
		result.setStateReason(PortFiltered, "no-response")
	}

	resultCh <- result
}

// scanPortWindow examines TCP window size in RST responses.
func scanPortWindow(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}

	if ctx.Err() != nil {
		result.State = PortFiltered
		resultCh <- result
		return
	}

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
	case <-ctx.Done():
		result.setStateReason(PortFiltered, "no-response")
	case resp := <-responseCh:
		if resp.flags&tcpRST != 0 {
			if resp.window > 0 {
				result.setStateReason(PortOpen, "window-nonzero")
			} else {
				result.setStateReason(PortClosed, "reset")
			}
		} else {
			result.setStateReason(PortFiltered, "no-response")
		}
	case <-time.After(timeout):
		result.setStateReason(PortFiltered, "no-response")
	}

	resultCh <- result
}

type rawResponse struct {
	flags  uint16
	window uint16
}

// listenForResponse listens for a TCP response from the target.
func listenForResponse(laddr, raddr string, dport, sport uint16, ch chan<- rawResponse, timeout time.Duration) {
	proto := ipProtocol(laddr, "tcp")
	network := "ip4"
	if IsIPv6(laddr) {
		network = "ip6"
	}
	listenAddr, err := net.ResolveIPAddr(network, laddr)
	if err != nil {
		return
	}

	conn, err := net.ListenIP(proto, listenAddr)
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

		srcPort := binary.BigEndian.Uint16(buf[0:2])
		dstPort := binary.BigEndian.Uint16(buf[2:4])

		if srcPort != dport || dstPort != sport {
			continue
		}

		flags := binary.BigEndian.Uint16(buf[12:14]) & 0x003f
		window := binary.BigEndian.Uint16(buf[14:16])

		ch <- rawResponse{flags: flags, window: window}
		return
	}
}

// sendTCPPacket constructs and sends a raw TCP packet with the specified flags.
func sendTCPPacket(laddr, raddr string, sport, dport, flags uint16) error {
	op := []tcpOption{
		{Kind: 2, Length: 4, Data: []byte{0x05, 0xb4}},
		{Kind: 0},
	}

	dataOffset := uint16(0x8000)
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

	conn, err := net.Dial(ipProtocol(raddr, "tcp"), raddr)
	if err != nil {
		return err
	}
	defer conn.Close()

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
