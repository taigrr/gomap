package gomap

import (
	"net"
	"strings"
)

// LookupMACVendor returns the vendor name for a given MAC address.
// Accepts any standard MAC format (colon, dash, or no separator).
// Returns empty string if the OUI is not found.
func LookupMACVendor(mac string) string {
	// Normalize: remove separators, uppercase
	mac = strings.ToUpper(mac)
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, ".", "")

	if len(mac) < 6 {
		return ""
	}

	prefix := mac[:6]
	if vendor, ok := MACPrefixes[prefix]; ok {
		return vendor
	}
	return ""
}

// LookupMACVendorHW returns the vendor name for a net.HardwareAddr.
func LookupMACVendorHW(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}
	prefix := strings.ToUpper(macHex(mac[:3]))
	if vendor, ok := MACPrefixes[prefix]; ok {
		return vendor
	}
	return ""
}

func macHex(b []byte) string {
	const hexDigit = "0123456789ABCDEF"
	buf := make([]byte, len(b)*2)
	for i, v := range b {
		buf[i*2] = hexDigit[v>>4]
		buf[i*2+1] = hexDigit[v&0x0f]
	}
	return string(buf)
}
