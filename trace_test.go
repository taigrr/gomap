package gomap

import (
	"bytes"
	"strings"
	"testing"
)

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

func TestTracerNilSafe(t *testing.T) {
	var tr *tracer
	// Should not panic on nil tracer
	tr.tracePacket(PacketSent, "TCP", "1.2.3.4", 80, "5.6.7.8", 443, "S")
	tr.traceConnect(PacketSent, "TCP", "1.2.3.4", 80, "connect()")
}

func TestTracerOutput(t *testing.T) {
	var buf bytes.Buffer
	tr := newTracer(&buf)

	tr.tracePacket(PacketSent, "TCP", "1.2.3.4", 12345, "5.6.7.8", 80, "S")
	tr.traceConnect(PacketReceived, "TCP", "5.6.7.8", 80, "Connected")

	output := buf.String()
	if !strings.Contains(output, "SENT") {
		t.Error("expected SENT in trace output")
	}
	if !strings.Contains(output, "RCVD") {
		t.Error("expected RCVD in trace output")
	}
	if !strings.Contains(output, "1.2.3.4:12345") {
		t.Error("expected source address in trace output")
	}
}
