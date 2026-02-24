package gomap

import "testing"

func TestTCPFlagString(t *testing.T) {
	tests := []struct {
		scanType ScanType
		want     string
	}{
		{SYNScan, "S"},
		{FINScan, "F"},
		{XmasScan, "FPU"},
		{NullScan, ""},
		{ACKScan, "A"},
		{WindowScan, "A"},
		{MaimonScan, "FA"},
		{ConnectScan, ""},
	}
	for _, tt := range tests {
		got := tcpFlagString(tt.scanType)
		if got != tt.want {
			t.Errorf("tcpFlagString(%v) = %q, want %q", tt.scanType, got, tt.want)
		}
	}
}

func TestInitTraceTimer(t *testing.T) {
	// Should not panic on multiple calls
	initTraceTimer()
	initTraceTimer()
}
