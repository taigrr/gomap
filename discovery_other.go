//go:build !linux

package gomap

import (
	"context"
	"net"
	"time"
)

// probeICMP attempts ICMP ping, falls back to TCP connect.
func probeICMP(ctx context.Context, host string, timeout time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}

	conn, err := net.DialTimeout("ip4:icmp", host, timeout)
	if err != nil {
		return probeTCPConnect(ctx, host, []int{80, 443}, timeout)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}
	conn.SetDeadline(deadline)

	msg := []byte{8, 0, 0, 0, 0, 1, 0, 1}
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
func probeTCPSYN(ctx context.Context, host string, ports []int, timeout time.Duration) bool {
	return probeTCPConnect(ctx, host, ports, timeout)
}

// probeTCPACK falls back to TCP connect on non-Linux.
func probeTCPACK(ctx context.Context, host string, ports []int, timeout time.Duration) bool {
	return probeTCPConnect(ctx, host, ports, timeout)
}

// probeARP is not supported on non-Linux platforms.
func probeARP(ctx context.Context, host string, timeout time.Duration) bool {
	return false
}
