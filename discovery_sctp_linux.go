//go:build linux

package gomap

import (
	"context"
	"net"
	"time"
)

// probeSCTPInit sends an SCTP INIT chunk to detect hosts (-PY).
func probeSCTPInit(ctx context.Context, host string, ports []int, timeout time.Duration) bool {
	laddr, err := GetLocalAddr(host)
	if err != nil {
		return false
	}

	for _, port := range ports {
		if ctx.Err() != nil {
			return false
		}

		proto := ipProtocol(laddr, "sctp")
		network := "ip4"
		if IsIPv6(laddr) {
			network = "ip6"
		}
		listenAddr, err := net.ResolveIPAddr(network, laddr)
		if err != nil {
			continue
		}

		conn, err := net.ListenIP(proto, listenAddr)
		if err != nil {
			// Fall back to TCP connect
			return probeTCPConnect(ctx, host, ports, timeout)
		}

		conn.SetDeadline(time.Now().Add(timeout))

		// Build minimal SCTP INIT chunk
		init := buildSCTPInit(uint16(port))
		raddr, err := net.ResolveIPAddr(network, host)
		if err != nil {
			conn.Close()
			continue
		}

		_, err = conn.WriteTo(init, raddr)
		if err != nil {
			conn.Close()
			continue
		}

		// Listen for any SCTP response
		buf := make([]byte, 1024)
		n, _, err := conn.ReadFrom(buf)
		conn.Close()
		if err == nil && n > 0 {
			return true
		}
	}
	return false
}

func buildSCTPInit(dport uint16) []byte {
	// Minimal SCTP packet: common header (12 bytes) + INIT chunk (20 bytes)
	pkt := make([]byte, 32)
	// Source port (2 bytes, big-endian)
	sport := uint16(randomPort(10000, 65535))
	pkt[0] = byte(sport >> 8)
	pkt[1] = byte(sport)
	// Dest port
	pkt[2] = byte(dport >> 8)
	pkt[3] = byte(dport)
	// Verification tag (0 for INIT)
	// Checksum (simplified — set to 0)

	// INIT chunk
	pkt[12] = 1 // chunk type = INIT
	pkt[13] = 0 // flags
	pkt[14] = 0 // length (20)
	pkt[15] = 20
	// Initiate tag
	pkt[16] = 0x12
	pkt[17] = 0x34
	pkt[18] = 0x56
	pkt[19] = 0x78
	// A-RWND
	pkt[20] = 0
	pkt[21] = 0
	pkt[22] = 0xFF
	pkt[23] = 0xFF
	// Number of outbound/inbound streams
	pkt[24] = 0
	pkt[25] = 1
	pkt[26] = 0
	pkt[27] = 1
	// Initial TSN
	pkt[28] = 0
	pkt[29] = 0
	pkt[30] = 0
	pkt[31] = 1

	return pkt
}
