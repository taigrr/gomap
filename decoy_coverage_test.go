package gomap

import (
	"net"
	"testing"
)

func TestRandomPublicIPv6(t *testing.T) {
	ip := randomPublicIPv6()
	if ip == nil {
		t.Fatal("randomPublicIPv6 returned nil")
	}
	if len(ip) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(ip))
	}
	// Should start with 0x2x (global unicast 2000::/3)
	if ip[0]&0xf0 != 0x20 {
		t.Errorf("first nibble should be 2, got 0x%02x", ip[0])
	}
}

func TestGenerateRandomDecoysIPv6(t *testing.T) {
	dc, err := GenerateRandomDecoys(3, "2001:db8::1", true)
	if err != nil {
		t.Fatal(err)
	}
	resolved := dc.ResolvedIPs()
	if len(resolved) != 4 { // 3 decoys + 1 real (ME)
		t.Errorf("expected 4 IPs, got %d", len(resolved))
	}

	// The real IP should appear exactly once
	realIP := net.ParseIP("2001:db8::1")
	count := 0
	for _, ip := range resolved {
		if ip.Equal(realIP) {
			count++
		}
	}
	if count != 1 {
		t.Errorf("real IP should appear exactly once, found %d", count)
	}
}

func TestResolvedIPsNil(t *testing.T) {
	var dc *DecoyConfig
	if ips := dc.ResolvedIPs(); ips != nil {
		t.Error("nil DecoyConfig should return nil IPs")
	}
}
