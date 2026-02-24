//go:build !linux

package gomap

import (
	"context"
	"time"
)

// scanPortSCTPInit falls back to filtered on non-Linux platforms.
func scanPortSCTPInit(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}
	result.setStateReason(PortFiltered, "sctp-init-requires-linux")
	resultCh <- result
}

// scanPortSCTPCookieEcho falls back to filtered on non-Linux platforms.
func scanPortSCTPCookieEcho(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}
	result.setStateReason(PortFiltered, "sctp-cookie-echo-requires-linux")
	resultCh <- result
}
