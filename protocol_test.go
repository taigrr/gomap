package gomap

import "testing"

func TestLookupProtocolName(t *testing.T) {
	tests := []struct {
		proto int
		want  string
	}{
		{1, "icmp"},
		{6, "tcp"},
		{17, "udp"},
		{132, "sctp"},
		{255, "proto-255"},
	}
	for _, tt := range tests {
		got := lookupProtocolName(tt.proto)
		if got != tt.want {
			t.Errorf("lookupProtocolName(%d) = %q, want %q", tt.proto, got, tt.want)
		}
	}
}

func TestDefaultProtocols(t *testing.T) {
	protos := defaultProtocols()
	if len(protos) == 0 {
		t.Error("defaultProtocols() should not be empty")
	}
	// Should contain ICMP(1), TCP(6), UDP(17)
	has := make(map[int]bool)
	for _, p := range protos {
		has[p] = true
	}
	for _, want := range []int{1, 6, 17} {
		if !has[want] {
			t.Errorf("defaultProtocols() missing protocol %d", want)
		}
	}
}
