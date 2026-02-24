//go:build linux

package gomap

import (
	"crypto/rand"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// SpoofMAC changes the MAC address of a network interface.
// mac can be: a specific MAC ("00:11:22:33:44:55"), a vendor prefix
// ("Dell", "Apple"), or "0" for a fully random MAC.
// Returns a restore function to set the original MAC back.
func SpoofMAC(iface, mac string) (restore func() error, err error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}

	originalMAC := ifi.HardwareAddr.String()

	var newMAC string
	switch {
	case mac == "0":
		newMAC = randomMAC()
	case isMAC(mac):
		newMAC = mac
	default:
		// Treat as vendor prefix — look up OUI
		prefix := lookupVendorPrefix(mac)
		if prefix == "" {
			return nil, fmt.Errorf("unknown vendor: %s", mac)
		}
		newMAC = prefix + ":" + randomMACsuffix()
	}

	if err := setMAC(iface, newMAC); err != nil {
		return nil, err
	}

	restoreFn := func() error {
		return setMAC(iface, originalMAC)
	}

	return restoreFn, nil
}

func setMAC(iface, mac string) error {
	// Take interface down, set MAC, bring it back up
	if err := exec.Command("ip", "link", "set", iface, "down").Run(); err != nil {
		return fmt.Errorf("bringing %s down: %w", iface, err)
	}
	if err := exec.Command("ip", "link", "set", iface, "address", mac).Run(); err != nil {
		exec.Command("ip", "link", "set", iface, "up").Run()
		return fmt.Errorf("setting MAC on %s: %w", iface, err)
	}
	return exec.Command("ip", "link", "set", iface, "up").Run()
}

func isMAC(s string) bool {
	_, err := net.ParseMAC(s)
	return err == nil
}

func randomMAC() string {
	b := make([]byte, 6)
	rand.Read(b)
	b[0] = (b[0] | 0x02) & 0xfe // locally administered, unicast
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func randomMACsuffix() string {
	b := make([]byte, 3)
	rand.Read(b)
	return fmt.Sprintf("%02x:%02x:%02x", b[0], b[1], b[2])
}

// lookupVendorPrefix finds an OUI prefix for a vendor name.
func lookupVendorPrefix(vendor string) string {
	vendor = strings.ToLower(vendor)
	prefixes := MACPrefixes()
	for prefix, name := range prefixes {
		if strings.Contains(strings.ToLower(name), vendor) {
			// Convert "AABBCC" to "AA:BB:CC"
			if len(prefix) == 6 {
				return prefix[0:2] + ":" + prefix[2:4] + ":" + prefix[4:6]
			}
			return prefix
		}
	}
	return ""
}
