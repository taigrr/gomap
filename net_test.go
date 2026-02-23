package gomap

import (
	"net"
	"testing"
)

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"::1", true},
		{"2001:db8::1", true},
		{"::ffff:192.168.1.1", false}, // mapped IPv4
		{"invalid", false},
	}
	for _, tt := range tests {
		if got := IsIPv6(tt.addr); got != tt.want {
			t.Errorf("IsIPv6(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestSelectIP(t *testing.T) {
	v4 := net.ParseIP("192.168.1.1")
	v6 := net.ParseIP("2001:db8::1")

	// Prefer IPv4
	got := selectIP([]net.IP{v4, v6}, false)
	if !got.Equal(v4) {
		t.Errorf("selectIP(preferV4) = %s, want %s", got, v4)
	}

	// Prefer IPv6
	got = selectIP([]net.IP{v4, v6}, true)
	if !got.Equal(v6) {
		t.Errorf("selectIP(preferV6) = %s, want %s", got, v6)
	}

	// Only IPv4 available, prefer IPv6 → fallback to IPv4
	got = selectIP([]net.IP{v4}, true)
	if !got.Equal(v4) {
		t.Errorf("selectIP(onlyV4, preferV6) = %s, want %s", got, v4)
	}
}

func TestCreateHostRangeV4(t *testing.T) {
	hosts := CreateHostRange("192.168.1.0/30")
	// /30 = 4 addresses: .0 (network), .1, .2, .3 (broadcast)
	// CreateHostRange excludes first and last
	if len(hosts) != 2 {
		t.Errorf("CreateHostRange(/30) = %d hosts, want 2", len(hosts))
	}
}

func TestCreateHostRangeV6(t *testing.T) {
	hosts := CreateHostRange("2001:db8::/126")
	// /126 = 4 addresses, exclude first and last = 2
	if len(hosts) != 2 {
		t.Errorf("CreateHostRange(v6 /126) = %d hosts, want 2", len(hosts))
	}

	// Too large range returns nil
	hosts = CreateHostRange("2001:db8::/64")
	if hosts != nil {
		t.Errorf("CreateHostRange(v6 /64) should return nil, got %d hosts", len(hosts))
	}
}

func TestIpProtocol(t *testing.T) {
	if got := ipProtocol("192.168.1.1", "tcp"); got != "ip4:tcp" {
		t.Errorf("ipProtocol(v4, tcp) = %q", got)
	}
	if got := ipProtocol("2001:db8::1", "tcp"); got != "ip6:tcp" {
		t.Errorf("ipProtocol(v6, tcp) = %q", got)
	}
}
