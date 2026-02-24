//go:build linux

package gomap

import (
	"context"
	"net"
	"time"
)

// probeICMP sends an ICMP echo request.
func probeICMP(ctx context.Context, host string, timeout time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}

	proto := "ip4:icmp"
	if IsIPv6(host) {
		proto = "ip6:ipv6-icmp"
	}
	conn, err := net.DialTimeout(proto, host, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}
	conn.SetDeadline(deadline)

	echoType := byte(8) // ICMPv4 Echo Request
	if IsIPv6(host) {
		echoType = 128 // ICMPv6 Echo Request
	}
	msg := []byte{
		echoType, 0, // Type, Code: 0
		0, 0, // Checksum
		0, 1, // Identifier
		0, 1, // Sequence number
	}
	cs := icmpChecksum(msg)
	msg[2] = byte(cs >> 8)
	msg[3] = byte(cs)

	_, err = conn.Write(msg)
	if err != nil {
		return false
	}

	buf := make([]byte, readBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}

	if IsIPv6(host) {
		// ICMPv6: no IP header in response, type 129 = echo reply
		if n >= 4 && buf[0] == 129 {
			return true
		}
	} else if n >= 20 {
		// ICMPv4: skip 20-byte IP header, type 0 = echo reply
		icmpOffset := 20
		if n > icmpOffset && buf[icmpOffset] == 0 {
			return true
		}
	}
	return false
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
}

// probeTCPSYN sends a SYN packet to detect hosts.
func probeTCPSYN(ctx context.Context, host string, ports []int, timeout time.Duration) bool {
	laddr, err := GetLocalAddr(host)
	if err != nil || !canSocketBind(laddr) {
		return probeTCPConnect(ctx, host, ports, timeout)
	}

	for _, port := range ports {
		if ctx.Err() != nil {
			return false
		}
		responseCh := make(chan rawResponse, 1)
		sport := uint16(randomPort(ephemeralPortMin, ephemeralPortMax))

		go listenForResponse(laddr, host, uint16(port), sport, responseCh, timeout)
		time.Sleep(5 * time.Millisecond)
		sendTCPPacket(laddr, host, sport, uint16(port), tcpSYN)

		select {
		case <-ctx.Done():
			return false
		case resp := <-responseCh:
			if resp.flags&(tcpSYN|tcpRST|tcpACK) != 0 {
				return true
			}
		case <-time.After(timeout):
			continue
		}
	}
	return false
}

// probeTCPACK sends an ACK packet to detect hosts.
func probeTCPACK(ctx context.Context, host string, ports []int, timeout time.Duration) bool {
	laddr, err := GetLocalAddr(host)
	if err != nil || !canSocketBind(laddr) {
		return probeTCPConnect(ctx, host, ports, timeout)
	}

	for _, port := range ports {
		if ctx.Err() != nil {
			return false
		}
		responseCh := make(chan rawResponse, 1)
		sport := uint16(randomPort(ephemeralPortMin, ephemeralPortMax))

		go listenForResponse(laddr, host, uint16(port), sport, responseCh, timeout)
		time.Sleep(5 * time.Millisecond)
		sendTCPPacket(laddr, host, sport, uint16(port), tcpACK)

		select {
		case <-ctx.Done():
			return false
		case resp := <-responseCh:
			if resp.flags&tcpRST != 0 {
				return true
			}
		case <-time.After(timeout):
			continue
		}
	}
	return false
}

// probeARP uses ARP-based host discovery on the local subnet.
func probeARP(ctx context.Context, host string, timeout time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	_ = probeTCPConnect(ctx, host, []int{80}, timeout)

	table, err := LoadARPTable()
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)
	for _, entry := range table {
		if entry.IP.Equal(ip) {
			return true
		}
	}
	return false
}
