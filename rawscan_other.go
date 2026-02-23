//go:build !linux

package gomap

import (
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

// scanPortRaw is not supported on non-Linux platforms.
// Falls back to connect scan.
func scanPortRaw(resultCh chan<- PortResult, hostname, service string, port int, laddr string, flags uint16, timeout time.Duration) {
	scanPortConnect(resultCh, "tcp", hostname, service, port, timeout)
}

// scanPortACK is not supported on non-Linux platforms.
func scanPortACK(resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration) {
	// Cannot determine filtered/unfiltered without raw sockets
	result := PortResult{Port: port, Service: service, State: PortUnfiltered}
	resultCh <- result
}

// scanPortWindow is not supported on non-Linux platforms.
func scanPortWindow(resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration) {
	scanPortConnect(resultCh, "tcp", hostname, service, port, timeout)
}
