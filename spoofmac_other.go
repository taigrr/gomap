//go:build !linux

package gomap

import "fmt"

func SpoofMAC(iface, mac string) (restore func() error, err error) {
	return nil, fmt.Errorf("MAC spoofing requires Linux")
}
