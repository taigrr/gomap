package gomap

import (
	"net"
	"testing"
)

func TestParseDecoys(t *testing.T) {
	dc, err := ParseDecoys("RND,ME,RND", "192.168.1.100")
	if err != nil {
		t.Fatal(err)
	}
	ips := dc.ResolvedIPs()
	if len(ips) != 3 {
		t.Fatalf("expected 3 IPs, got %d", len(ips))
	}
	// ME should be at index 1
	if !ips[1].Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("ME position wrong: got %s", ips[1])
	}
	// RND should be public IPs
	for i, ip := range ips {
		if i == 1 {
			continue
		}
		if !isPublicIP(ip) {
			t.Errorf("decoy %d is not public: %s", i, ip)
		}
	}
}

func TestParseDecoysNoME(t *testing.T) {
	dc, err := ParseDecoys("RND,RND", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// Should append ME at end
	ips := dc.ResolvedIPs()
	if len(ips) != 3 {
		t.Fatalf("expected 3 IPs (2 RND + ME appended), got %d", len(ips))
	}
	if !ips[2].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("ME not appended: last IP is %s", ips[2])
	}
}

func TestParseDecoysExplicitIPs(t *testing.T) {
	dc, err := ParseDecoys("1.2.3.4,5.6.7.8,ME", "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	ips := dc.ResolvedIPs()
	if len(ips) != 3 {
		t.Fatalf("expected 3 IPs, got %d", len(ips))
	}
	if ips[0].String() != "1.2.3.4" {
		t.Errorf("first decoy = %s, want 1.2.3.4", ips[0])
	}
}

func TestGenerateRandomDecoys(t *testing.T) {
	dc, err := GenerateRandomDecoys(5, "192.168.1.1", false)
	if err != nil {
		t.Fatal(err)
	}
	ips := dc.ResolvedIPs()
	if len(ips) != 6 { // 5 decoys + 1 real
		t.Fatalf("expected 6 IPs, got %d", len(ips))
	}
	// Real IP should appear exactly once
	count := 0
	for _, ip := range ips {
		if ip.Equal(net.ParseIP("192.168.1.1")) {
			count++
		}
	}
	if count != 1 {
		t.Errorf("real IP appears %d times, want 1", count)
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"127.0.0.1", false},
		{"0.0.0.0", false},
		{"224.0.0.1", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := isPublicIP(ip); got != tt.want {
			t.Errorf("isPublicIP(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
