//go:build !linux

package gomap

import (
	"context"
	"time"
)

// TCP flag constants (needed for cross-platform compilation)
const (
	tcpFIN uint16 = 0x0001
	tcpSYN uint16 = 0x0002
	tcpRST uint16 = 0x0004
	tcpPSH uint16 = 0x0008
	tcpACK uint16 = 0x0010
	tcpURG uint16 = 0x0020
)

// scanPortRaw falls back to connect scan on non-Linux.
func scanPortRaw(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, laddr string, flags uint16, timeout time.Duration) {
	scanPortConnect(ctx, resultCh, "tcp", hostname, service, port, timeout)
}

// scanPortACK falls back on non-Linux.
func scanPortACK(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration) {
	result := PortResult{Port: port, Service: service, State: PortUnfiltered}
	resultCh <- result
}

// scanPortWindow falls back to connect scan on non-Linux.
func scanPortWindow(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration) {
	scanPortConnect(ctx, resultCh, "tcp", hostname, service, port, timeout)
}
