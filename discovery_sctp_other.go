//go:build !linux

package gomap

import (
	"context"
	"time"
)

// probeSCTPInit falls back to TCP connect on non-Linux.
func probeSCTPInit(ctx context.Context, host string, ports []int, timeout time.Duration) bool {
	return probeTCPConnect(ctx, host, ports, timeout)
}
