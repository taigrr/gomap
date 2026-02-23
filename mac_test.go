package gomap

import (
	"net"
	"testing"
)

func TestLookupMACVendor(t *testing.T) {
	tests := []struct {
		mac  string
		want string // partial match
	}{
		{"00:00:0C:12:34:56", "Cisco"},  // Cisco Systems
		{"00-00-0C-12-34-56", "Cisco"},  // dash format
		{"00000C123456", "Cisco"},       // no separator
		{"00:50:56:12:34:56", "VMware"}, // VMware
		{"AA:BB:CC:DD:EE:FF", ""},       // unknown
		{"short", ""},                   // too short
		{"", ""},                        // empty
	}
	for _, tt := range tests {
		got := LookupMACVendor(tt.mac)
		if tt.want == "" && got != "" {
			t.Errorf("LookupMACVendor(%q) = %q, want empty", tt.mac, got)
		}
		if tt.want != "" && got == "" {
			t.Errorf("LookupMACVendor(%q) = empty, want to contain %q", tt.mac, tt.want)
		}
	}
}

func TestLookupMACVendorHW(t *testing.T) {
	// Cisco OUI: 00:00:0C
	mac, _ := net.ParseMAC("00:00:0C:12:34:56")
	vendor := LookupMACVendorHW(mac)
	if vendor == "" {
		t.Error("expected Cisco vendor for 00:00:0C, got empty")
	}

	// Too short
	short := net.HardwareAddr{0x00, 0x00}
	if LookupMACVendorHW(short) != "" {
		t.Error("expected empty for short MAC")
	}
}

func TestMACPrefixesNotEmpty(t *testing.T) {
	if len(MACPrefixes) == 0 {
		t.Error("MACPrefixes should not be empty")
	}
	if len(MACPrefixes) < 30000 {
		t.Errorf("MACPrefixes has %d entries, expected at least 30000", len(MACPrefixes))
	}
}

func TestLookupMACVendorCaseInsensitive(t *testing.T) {
	v1 := LookupMACVendor("00:00:0c:12:34:56") // lowercase
	v2 := LookupMACVendor("00:00:0C:12:34:56") // uppercase
	if v1 != v2 {
		t.Errorf("MAC lookup should be case-insensitive: %q vs %q", v1, v2)
	}
}
