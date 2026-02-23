//go:build !linux

package gomap

import (
	"net"
	"time"
)

// probeICMP uses an unprivileged ICMP ping via UDP on non-Linux platforms.
// This uses Go's net.Dial with "ip4:icmp" which may not work without privileges.
// Falls back to TCP connect if ICMP fails.
func probeICMP(host string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("ip4:icmp", host, timeout)
	if err != nil {
		// ICMP not available without privileges, fall back to TCP
		return probeTCPConnect(host, []int{80, 443}, timeout)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	msg := []byte{
		8, 0,
		0, 0,
		0, 1,
		0, 1,
	}

	var sum uint32
	for i := 0; i < len(msg)-1; i += 2 {
		sum += uint32(msg[i])<<8 | uint32(msg[i+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	cs := ^uint16(sum)
	msg[2] = byte(cs >> 8)
	msg[3] = byte(cs)

	_, err = conn.Write(msg)
	if err != nil {
		return false
	}

	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	return err == nil
}

// probeTCPSYN falls back to TCP connect on non-Linux.
func probeTCPSYN(host string, ports []int, timeout time.Duration) bool {
	return probeTCPConnect(host, ports, timeout)
}

// probeTCPACK falls back to TCP connect on non-Linux.
func probeTCPACK(host string, ports []int, timeout time.Duration) bool {
	return probeTCPConnect(host, ports, timeout)
}

// probeARP is not supported on non-Linux platforms.
func probeARP(host string, timeout time.Duration) bool {
	return false
}
