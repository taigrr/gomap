//go:build !linux

package gomap

import (
	"context"
	"fmt"
	"time"
)

// sendOSProbesImpl is not supported on non-Linux platforms.
func sendOSProbesImpl(ctx context.Context, laddr, raddr string, openPort, closedPort int, timeout time.Duration) (*OSFingerprint, error) {
	return nil, fmt.Errorf("OS detection: %w", ErrLinuxRequired)
}
