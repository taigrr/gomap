//go:build !linux

package gomap

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

// traceHopImpl on non-Linux platforms uses TCP connect with short timeouts
// as a basic traceroute approximation. Full ICMP-based traceroute requires
// raw sockets which need platform-specific implementations.
func traceHopImpl(ctx context.Context, target string, ttl int, opts TracerouteOptions) (string, time.Duration, error) {
	// Fallback: TCP connect to detect reachability at the destination.
	// This won't show intermediate hops but at least confirms the target.
	if ttl > 1 {
		return "", 0, fmt.Errorf("intermediate hop detection requires raw sockets (Linux only)")
	}

	addr := net.JoinHostPort(target, strconv.Itoa(opts.Port))
	start := time.Now()

	d := net.Dialer{Timeout: opts.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", 0, err
	}
	conn.Close()

	return target, time.Since(start), nil
}
