//go:build !linux

package gomap

import (
	"context"
	"time"
)

// IdleScanConfig holds the zombie host configuration for idle scanning.
type IdleScanConfig struct {
	ZombieHost string
	ZombiePort int
}

func scanPortIdle(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration, zombie IdleScanConfig) {
	result := PortResult{Port: port, Service: service}
	result.setStateReason(PortFiltered, "idle scan requires Linux")
	resultCh <- result
}
