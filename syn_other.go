//go:build !linux

package gomap

import "fmt"

// scanPortSyn is not supported on non-Linux platforms.
// Falls back to connect scan.
func scanPortSyn(resultCh chan<- PortResult, protocol, hostname, service string, port int, laddr string) {
	scanPortConnect(resultCh, protocol, hostname, service, port, 3*1e9)
}

// ErrStealthNotSupported is returned when stealth scanning is attempted on
// a platform that doesn't support raw sockets.
var ErrStealthNotSupported = fmt.Errorf("stealth (SYN) scanning is only supported on Linux")
