//go:build !linux

package gomap

import "fmt"

func sendFragmentedPacket(laddr, raddr string, sport, dport, flags uint16, mtu int) error {
	return fmt.Errorf("IP fragmentation requires Linux")
}
