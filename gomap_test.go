package gomap

import (
	"net"
	"testing"
)

func TestLookupService(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{22, "SSH Remote Login Protocol"},
		{80, "World Wide Web HTTP"},
		{443, "HTTP protocol over TLS/SSL"},
		{99999, "unknown"},
	}
	for _, tt := range tests {
		got := LookupService(tt.port)
		if got != tt.want {
			t.Errorf("LookupService(%d) = %q, want %q", tt.port, got, tt.want)
		}
	}
}

func TestCreateHostRange(t *testing.T) {
	hosts := CreateHostRange("192.168.1.0/30")
	// /30 = 4 IPs, minus network and broadcast = 2 hosts
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}
	if len(hosts) > 0 && hosts[0] != "192.168.1.1" {
		t.Errorf("expected first host 192.168.1.1, got %s", hosts[0])
	}
}

func TestCreateHostRangeInvalid(t *testing.T) {
	hosts := CreateHostRange("not-a-cidr")
	if hosts != nil {
		t.Errorf("expected nil for invalid CIDR, got %v", hosts)
	}
}

func TestGetLocalIP(t *testing.T) {
	ip, err := GetLocalIP()
	if err != nil {
		t.Skipf("No local IP found: %v", err)
	}
	if ip == "" {
		t.Error("GetLocalIP returned empty string")
	}
	t.Logf("Local IP: %s", ip)
}

func TestGetLocalRange(t *testing.T) {
	r := GetLocalRange()
	if r == "" {
		t.Error("GetLocalRange returned empty string")
	}
	t.Logf("Local range: %s", r)
}

func TestScanResultString(t *testing.T) {
	r := &ScanResult{
		Hostname: "localhost",
		IP:       []net.IP{net.IPv4(127, 0, 0, 1)},
		Ports: []PortResult{
			{Port: 22, Open: true, Service: "ssh"},
			{Port: 80, Open: false, Service: "http"},
		},
	}
	s := r.String()
	if s == "" {
		t.Error("String() returned empty")
	}
}

func TestScanResultOpenPorts(t *testing.T) {
	r := &ScanResult{
		Ports: []PortResult{
			{Port: 22, Open: true, Service: "ssh"},
			{Port: 80, Open: false, Service: "http"},
			{Port: 443, Open: true, Service: "https"},
		},
	}
	open := r.OpenPorts()
	if len(open) != 2 {
		t.Errorf("expected 2 open ports, got %d", len(open))
	}
}
