package gomap

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRangeScanResultString(t *testing.T) {
	results := RangeScanResult{
		{
			Hostname: "host1",
			IP:       []net.IP{net.IPv4(10, 0, 0, 1)},
			Ports: []PortResult{
				{Port: 22, Open: true, State: PortOpen, Service: "ssh"},
			},
		},
		{
			Hostname: "host2",
			IP:       []net.IP{net.IPv4(10, 0, 0, 2)},
			Ports: []PortResult{
				{Port: 80, Open: false, State: PortClosed, Service: "http"},
			},
		},
	}
	s := results.String()
	if !strings.Contains(s, "host1") {
		t.Error("RangeScanResult.String() should contain host1")
	}
	if !strings.Contains(s, "host2") {
		t.Error("RangeScanResult.String() should contain host2")
	}
	if !strings.Contains(s, "22") {
		t.Error("should contain port 22")
	}
	if !strings.Contains(s, "No Open Ports") {
		t.Error("should contain 'No Open Ports' for host2")
	}
}

func TestScanResultStringNoIP(t *testing.T) {
	r := &ScanResult{
		Hostname: "noip.test",
		IP:       nil,
		Ports: []PortResult{
			{Port: 80, Open: true, State: PortOpen, Service: "http"},
		},
	}
	s := r.String()
	if !strings.Contains(s, "<unknown>") {
		t.Error("should show <unknown> when no IP")
	}
}

func TestScanResultStringUnknownHost(t *testing.T) {
	r := &ScanResult{
		Hostname: "Unknown",
		IP:       []net.IP{net.IPv4(10, 0, 0, 1)},
		Ports: []PortResult{
			{Port: 80, Open: false, State: PortClosed, Service: "http"},
		},
	}
	s := r.String()
	// For "Unknown" hostname with no open ports, no "No Open Ports" line is printed
	if strings.Contains(s, "No Open Ports") {
		t.Error("should NOT show 'No Open Ports' for Unknown hostname")
	}
}

func TestResultToJSONTimestamps(t *testing.T) {
	now := time.Now()
	r := &ScanResult{
		Hostname:  "ts.test",
		IP:        []net.IP{net.IPv4(1, 2, 3, 4)},
		StartTime: now,
		EndTime:   now.Add(5 * time.Second),
		Duration:  5 * time.Second,
		Ports: []PortResult{
			{Port: 443, Open: true, State: PortOpen, Service: "https", Protocol: "tcp", Reason: "syn-ack"},
		},
	}
	j, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}

	var parsed JSONResult
	if err := json.Unmarshal([]byte(j), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.StartTime == "" {
		t.Error("StartTime should be set")
	}
	if parsed.EndTime == "" {
		t.Error("EndTime should be set")
	}
	if parsed.Duration == "" {
		t.Error("Duration should be set")
	}
	if len(parsed.Ports) != 1 || parsed.Ports[0].Reason != "syn-ack" {
		t.Error("port reason should be preserved")
	}
}

func TestResultToJSONNoIP(t *testing.T) {
	r := &ScanResult{Hostname: "noip"}
	jr := resultToJSON(r)
	if jr.IP != "" {
		t.Errorf("expected empty IP, got %q", jr.IP)
	}
}

func TestPortResultSetStateReason(t *testing.T) {
	tests := []struct {
		state    PortState
		wantOpen bool
	}{
		{PortOpen, true},
		{PortOpenFiltered, true},
		{PortClosed, false},
		{PortFiltered, false},
		{PortUnfiltered, false},
	}
	for _, tt := range tests {
		pr := &PortResult{}
		pr.setStateReason(tt.state, "test")
		if pr.Open != tt.wantOpen {
			t.Errorf("setStateReason(%s): Open = %v, want %v", tt.state, pr.Open, tt.wantOpen)
		}
		if pr.Reason != "test" {
			t.Errorf("reason should be 'test', got %q", pr.Reason)
		}
	}
}

func TestScanResultJSONProtocolDefault(t *testing.T) {
	r := &ScanResult{
		Hostname: "test",
		IP:       []net.IP{net.IPv4(1, 1, 1, 1)},
		Ports: []PortResult{
			{Port: 80, Open: true, State: PortOpen, Protocol: ""},
		},
	}
	j, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	// Empty protocol should default to "tcp" in JSON
	if !strings.Contains(j, `"tcp"`) {
		t.Error("empty protocol should serialize as tcp")
	}
}
