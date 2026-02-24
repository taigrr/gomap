package gomap

import (
	"testing"
)

func TestPortsByRatio(t *testing.T) {
	ports := PortsByRatio(0.5) // very high ratio — should return very few ports
	if len(ports) > 10 {
		t.Errorf("expected few ports with ratio 0.5, got %d", len(ports))
	}

	ports = PortsByRatio(0.001) // low ratio — should return many ports
	if len(ports) < 100 {
		t.Errorf("expected many ports with ratio 0.001, got %d", len(ports))
	}
}

func TestExcludePorts(t *testing.T) {
	ports := []int{22, 80, 443, 8080, 8443}
	result, err := ExcludePorts(ports, "80,443")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 3 {
		t.Errorf("expected 3 ports, got %d: %v", len(result), result)
	}
	for _, p := range result {
		if p == 80 || p == 443 {
			t.Errorf("port %d should have been excluded", p)
		}
	}
}

func TestExcludePortsRange(t *testing.T) {
	ports := []int{20, 21, 22, 23, 24, 25, 80}
	result, err := ExcludePorts(ports, "20-24")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 ports, got %d: %v", len(result), result)
	}
}

func TestParseScanFlags(t *testing.T) {
	tests := []struct {
		spec string
		want uint16
		err  bool
	}{
		{"S", 0x0002, false},    // SYN
		{"SF", 0x0003, false},   // SYN+FIN
		{"SA", 0x0012, false},   // SYN+ACK
		{"SAPF", 0x001B, false}, // SYN+ACK+PSH+FIN
		{"0x29", 0x29, false},   // hex
		{"", 0, false},          // empty
		{"Z", 0, true},          // invalid flag
	}
	for _, tt := range tests {
		got, err := ParseScanFlags(tt.spec)
		if (err != nil) != tt.err {
			t.Errorf("ParseScanFlags(%q) error=%v, want error=%v", tt.spec, err, tt.err)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("ParseScanFlags(%q) = 0x%04x, want 0x%04x", tt.spec, got, tt.want)
		}
	}
}

func TestTopUDPPorts(t *testing.T) {
	ports := TopUDPPorts(10)
	if len(ports) == 0 {
		t.Error("TopUDPPorts(10) should return ports")
	}
	if len(ports) > 10 {
		t.Errorf("TopUDPPorts(10) returned %d ports", len(ports))
	}
}
