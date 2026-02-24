//go:build linux

package gomap

import (
	"context"
	"fmt"
	"net"
	"time"
)

// probeIPProtocol sends raw IP packets with specified protocol numbers (-PO).
// Any response (including ICMP protocol unreachable) indicates the host is alive.
func probeIPProtocol(ctx context.Context, host string, protocols []int, timeout time.Duration) bool {
	if len(protocols) == 0 {
		protocols = []int{1, 2, 4} // ICMP, IGMP, IPv4 (nmap defaults)
	}

	for _, proto := range protocols {
		if ctx.Err() != nil {
			return false
		}

		network := fmt.Sprintf("ip4:%d", proto)
		conn, err := net.DialTimeout(network, host, timeout)
		if err != nil {
			continue
		}

		conn.SetDeadline(time.Now().Add(timeout))
		// Send minimal data
		_, err = conn.Write([]byte{0})
		if err != nil {
			conn.Close()
			continue
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		conn.Close()
		if n > 0 || err == nil {
			return true
		}
		// Connection refused / ICMP unreachable = host is alive
		if isConnectionRefused(err) {
			return true
		}
	}
	return false
}
