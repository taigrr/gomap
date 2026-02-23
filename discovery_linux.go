//go:build linux

package gomap

import (
	"net"
	"time"
)

// probeICMP sends an ICMP echo request.
func probeICMP(host string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("ip4:icmp", host, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// ICMP echo request
	msg := []byte{
		8, 0, // Type: Echo Request, Code: 0
		0, 0, // Checksum (computed below)
		0, 1, // Identifier
		0, 1, // Sequence number
	}

	// Compute checksum
	cs := icmpChecksum(msg)
	msg[2] = byte(cs >> 8)
	msg[3] = byte(cs)

	_, err = conn.Write(msg)
	if err != nil {
		return false
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}

	// Verify we got an ICMP echo reply (type 0)
	if n >= 20 {
		// IP header is typically 20 bytes, ICMP starts after
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
func probeTCPSYN(host string, ports []int, timeout time.Duration) bool {
	laddr, err := GetLocalIP()
	if err != nil || !canSocketBind(laddr) {
		// Fall back to connect
		return probeTCPConnect(host, ports, timeout)
	}

	for _, port := range ports {
		responseCh := make(chan rawResponse, 1)
		sport := uint16(randomPort(10000, 65535))

		go listenForResponse(laddr, host, uint16(port), sport, responseCh, timeout)
		time.Sleep(5 * time.Millisecond)
		sendTCPPacket(laddr, host, sport, uint16(port), tcpSYN)

		select {
		case resp := <-responseCh:
			// Any TCP response means the host is alive
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
func probeTCPACK(host string, ports []int, timeout time.Duration) bool {
	laddr, err := GetLocalIP()
	if err != nil || !canSocketBind(laddr) {
		return probeTCPConnect(host, ports, timeout)
	}

	for _, port := range ports {
		responseCh := make(chan rawResponse, 1)
		sport := uint16(randomPort(10000, 65535))

		go listenForResponse(laddr, host, uint16(port), sport, responseCh, timeout)
		time.Sleep(5 * time.Millisecond)
		sendTCPPacket(laddr, host, sport, uint16(port), tcpACK)

		select {
		case resp := <-responseCh:
			// RST means the host is alive (regardless of firewall)
			if resp.flags&tcpRST != 0 {
				return true
			}
		case <-time.After(timeout):
			continue
		}
	}
	return false
}

// probeARP attempts ARP-based host discovery.
// Only works on the local subnet.
func probeARP(host string, timeout time.Duration) bool {
	// On Linux, we can use the ARP table after pinging
	// For now, try a TCP connect (which triggers ARP) and check the table
	_ = probeTCPConnect(host, []int{80}, timeout)

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
