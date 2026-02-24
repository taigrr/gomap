//go:build !linux

package gomap

import (
	"context"
	"time"
)

// probeIPProtocol falls back to ICMP ping on non-Linux.
func probeIPProtocol(ctx context.Context, host string, protocols []int, timeout time.Duration) bool {
	return probeICMP(ctx, host, timeout)
}
