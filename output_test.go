package gomap

import (
	"encoding/xml"
	"net"
	"strings"
	"testing"
	"time"
)

func TestScanResultToXML(t *testing.T) {
	r := &ScanResult{
		Hostname: "test.example.com",
		IP:       []net.IP{net.IPv4(10, 0, 0, 1)},
		Ports: []PortResult{
			{Port: 22, Open: true, State: PortOpen, Service: "ssh"},
			{Port: 80, Open: false, State: PortClosed, Service: "http"},
		},
	}

	data, err := r.ToXML(ConnectScan, time.Now(), "test")
	if err != nil {
		t.Fatalf("ToXML error: %v", err)
	}

	xmlStr := string(data)

	// Verify it's valid XML
	var nmapRun NmapRun
	if err := xml.Unmarshal(data, &nmapRun); err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}

	if nmapRun.Scanner != "gomap" {
		t.Errorf("scanner = %q, want gomap", nmapRun.Scanner)
	}
	if nmapRun.XMLOutputVersion != "1.05" {
		t.Errorf("xmloutputversion = %q, want 1.05", nmapRun.XMLOutputVersion)
	}
	if len(nmapRun.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(nmapRun.Hosts))
	}

	host := nmapRun.Hosts[0]
	if host.Address.Addr != "10.0.0.1" {
		t.Errorf("address = %q, want 10.0.0.1", host.Address.Addr)
	}
	if host.Status.State != "up" {
		t.Errorf("status = %q, want up", host.Status.State)
	}
	if host.Ports == nil || len(host.Ports.Ports) != 2 {
		t.Fatalf("expected 2 ports in XML")
	}

	// Verify XML header
	if !strings.HasPrefix(xmlStr, "<?xml") {
		t.Error("XML should start with <?xml header")
	}
}

func TestRangeScanResultToXML(t *testing.T) {
	results := RangeScanResult{
		{
			Hostname: "host1",
			IP:       []net.IP{net.IPv4(10, 0, 0, 1)},
			Ports:    []PortResult{{Port: 22, Open: true, State: PortOpen}},
		},
		{
			Hostname: "host2",
			IP:       []net.IP{net.IPv4(10, 0, 0, 2)},
			Ports:    []PortResult{{Port: 80, Open: false, State: PortClosed}},
		},
	}

	data, err := results.ToXML(ConnectScan, time.Now(), "test")
	if err != nil {
		t.Fatalf("ToXML error: %v", err)
	}

	var nmapRun NmapRun
	if err := xml.Unmarshal(data, &nmapRun); err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}

	if len(nmapRun.Hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(nmapRun.Hosts))
	}
	if nmapRun.RunStats.Hosts.Total != 2 {
		t.Errorf("total hosts = %d, want 2", nmapRun.RunStats.Hosts.Total)
	}
}

func TestScanResultToGrepable(t *testing.T) {
	r := &ScanResult{
		Hostname: "test.example.com",
		IP:       []net.IP{net.IPv4(10, 0, 0, 1)},
		Ports: []PortResult{
			{Port: 22, Open: true, State: PortOpen, Service: "ssh"},
			{Port: 80, Open: false, State: PortClosed, Service: "http"},
		},
	}

	out := r.ToGrepable()

	if !strings.Contains(out, "10.0.0.1") {
		t.Error("grepable should contain IP")
	}
	if !strings.Contains(out, "test.example.com") {
		t.Error("grepable should contain hostname")
	}
	if !strings.Contains(out, "22/open/tcp") {
		t.Error("grepable should contain open port 22")
	}
	if !strings.Contains(out, "80/closed/tcp") {
		t.Error("grepable should contain closed port 80")
	}
	if !strings.Contains(out, "Host:") {
		t.Error("grepable should have Host: prefix")
	}
	if !strings.Contains(out, "Ports:") {
		t.Error("grepable should have Ports: field")
	}
}

func TestRangeScanResultToGrepable(t *testing.T) {
	results := RangeScanResult{
		{
			Hostname: "host1",
			IP:       []net.IP{net.IPv4(10, 0, 0, 1)},
			Ports:    []PortResult{{Port: 22, Open: true, State: PortOpen, Service: "ssh"}},
		},
		{
			IP:    []net.IP{net.IPv4(10, 0, 0, 2)},
			Ports: []PortResult{{Port: 80, Open: false, State: PortClosed}},
		},
	}

	out := results.ToGrepable()
	lines := strings.Split(strings.TrimSpace(out), "\n")

	// Should have header + 2 host lines
	if len(lines) < 3 {
		t.Errorf("expected at least 3 lines, got %d", len(lines))
	}

	// Second host has no hostname
	if !strings.Contains(lines[2], "10.0.0.2 ()") {
		t.Errorf("expected empty hostname for second host, got: %s", lines[2])
	}
}

func TestGrepablePortSorting(t *testing.T) {
	r := &ScanResult{
		IP: []net.IP{net.IPv4(10, 0, 0, 1)},
		Ports: []PortResult{
			{Port: 443, Open: true, State: PortOpen},
			{Port: 22, Open: true, State: PortOpen},
			{Port: 80, Open: true, State: PortOpen},
		},
	}

	out := r.ToGrepable()
	// Ports should be sorted: 22, 80, 443
	idx22 := strings.Index(out, "22/")
	idx80 := strings.Index(out, "80/")
	idx443 := strings.Index(out, "443/")

	if idx22 > idx80 || idx80 > idx443 {
		t.Error("ports should be sorted in grepable output")
	}
}
