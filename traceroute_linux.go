//go:build linux

package gomap

import (
	"context"
	"net"
	"syscall"
	"time"
)

// traceHopImpl sends a UDP packet with a specific TTL and listens for the
// ICMP Time Exceeded response (or an ICMP Port Unreachable if we reached the target).
func traceHopImpl(ctx context.Context, target string, ttl int, opts TracerouteOptions) (string, time.Duration, error) {
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return "", 0, &net.OpError{Op: "traceroute", Err: net.InvalidAddrError(target)}
	}

	// Create a raw ICMP socket to receive replies
	recvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return "", 0, err
	}
	defer syscall.Close(recvFd)

	// Set timeout on receive socket
	tv := syscall.NsecToTimeval(opts.Timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(recvFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return "", 0, err
	}

	// Create a UDP socket for sending
	sendFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return "", 0, err
	}
	defer syscall.Close(sendFd)

	// Set the TTL
	if err := syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl); err != nil {
		return "", 0, err
	}

	// Build the target address — use a high port unlikely to be open
	destPort := 33434 + ttl
	var destAddr [4]byte
	copy(destAddr[:], targetIP.To4())

	start := time.Now()

	// Send a UDP packet
	sa := &syscall.SockaddrInet4{Port: destPort, Addr: destAddr}
	if err := syscall.Sendto(sendFd, []byte{0}, 0, sa); err != nil {
		return "", 0, err
	}

	// Receive ICMP reply
	buf := make([]byte, 512)
	for {
		if ctx.Err() != nil {
			return "", 0, ctx.Err()
		}

		n, from, err := syscall.Recvfrom(recvFd, buf, 0)
		if err != nil {
			return "", 0, err
		}

		rtt := time.Since(start)

		if n < 20 {
			continue
		}

		fromAddr, ok := from.(*syscall.SockaddrInet4)
		if !ok {
			continue
		}

		ip := net.IPv4(fromAddr.Addr[0], fromAddr.Addr[1], fromAddr.Addr[2], fromAddr.Addr[3]).String()

		// ICMP header starts after IP header (usually 20 bytes, but check IHL)
		ihl := int(buf[0]&0x0f) * 4
		if n < ihl+8 {
			continue
		}

		icmpType := buf[ihl]

		// Type 11 = Time Exceeded, Type 3 = Destination Unreachable
		if icmpType == 11 || icmpType == 3 {
			return ip, rtt, nil
		}

		// Type 0 = Echo Reply (shouldn't happen for UDP traceroute but accept it)
		if icmpType == 0 {
			return ip, rtt, nil
		}
	}
}
