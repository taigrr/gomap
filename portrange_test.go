package gomap

import "testing"

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		spec    string
		want    int // expected count
		wantErr bool
	}{
		{"80", 1, false},
		{"80,443", 2, false},
		{"1-5", 5, false},
		{"22,80-90,443", 13, false},
		{"80,80,80", 1, false}, // dedup
		{"-", 65535, false},    // all ports
		{"T:80,U:53", 2, false},
		{"0", 0, true},     // out of range
		{"99999", 0, true}, // out of range
		{"abc", 0, true},   // invalid
		{"5-3", 0, true},   // reversed range
		{"", 0, true},      // empty
	}

	for _, tt := range tests {
		ports, err := ParsePortRange(tt.spec)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParsePortRange(%q) expected error", tt.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortRange(%q) error: %v", tt.spec, err)
			continue
		}
		if len(ports) != tt.want {
			t.Errorf("ParsePortRange(%q) = %d ports, want %d", tt.spec, len(ports), tt.want)
		}
	}
}

func TestParsePortRangeValues(t *testing.T) {
	ports, err := ParsePortRange("22,80,443")
	if err != nil {
		t.Fatal(err)
	}
	expected := map[int]bool{22: true, 80: true, 443: true}
	for _, p := range ports {
		if !expected[p] {
			t.Errorf("unexpected port %d", p)
		}
	}
}

func TestParsePortRangeProtocolPrefix(t *testing.T) {
	ports, err := ParsePortRange("T:80,T:443,U:53")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 3 {
		t.Errorf("expected 3 ports, got %d", len(ports))
	}
}
