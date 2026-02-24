//go:build !linux

package gomap

import (
	"context"
	"fmt"
	"time"
)

// scanPortSyn falls back to connect scan on non-Linux platforms.
func scanPortSyn(ctx context.Context, resultCh chan<- PortResult, protocol, hostname, service string, port int, laddr string, timeout time.Duration) {
	scanPortConnect(ctx, resultCh, protocol, hostname, service, port, timeout, nil)
}

// ErrStealthNotSupported is returned when stealth scanning is attempted on
// a platform that doesn't support raw sockets.
var ErrStealthNotSupported = fmt.Errorf("stealth (SYN) scanning is only supported on Linux")
