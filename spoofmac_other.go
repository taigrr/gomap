//go:build !linux

package gomap

import "fmt"

// SpoofMAC is not supported on non-Linux platforms and returns ErrLinuxRequired.
func SpoofMAC(iface, mac string) (restore func() error, err error) {
	return nil, fmt.Errorf("MAC spoofing: %w", ErrLinuxRequired)
}
