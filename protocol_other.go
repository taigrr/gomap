//go:build !linux

package gomap

import (
	"context"
	"fmt"
)

// IPProtocolScan is not supported on non-Linux platforms.
func IPProtocolScan(ctx context.Context, host string, opts ScanOptions) ([]ProtocolResult, error) {
	return nil, fmt.Errorf("IP protocol scan requires Linux")
}
