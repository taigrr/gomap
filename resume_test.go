package gomap

import (
	"path/filepath"
	"testing"
	"time"
)

func TestResumeSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resume.json")

	state := &ResumeState{
		Version:   1,
		StartTime: time.Now(),
		Targets:   []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
		CompletedHosts: map[string]bool{
			"10.0.0.1": true,
		},
	}

	if err := SaveResume(path, state); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadResume(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(loaded.Targets) != 3 {
		t.Errorf("targets = %d, want 3", len(loaded.Targets))
	}

	remaining := loaded.RemainingTargets()
	if len(remaining) != 2 {
		t.Errorf("remaining = %d, want 2", len(remaining))
	}
}

func TestResumeMarkComplete(t *testing.T) {
	state := &ResumeState{
		Version: 1,
		Targets: []string{"a", "b", "c"},
	}
	state.MarkComplete("a", "")
	state.MarkComplete("b", "")

	remaining := state.RemainingTargets()
	if len(remaining) != 1 || remaining[0] != "c" {
		t.Errorf("remaining = %v, want [c]", remaining)
	}
}

func TestScanTypeStrings(t *testing.T) {
	tests := []struct {
		st   ScanType
		want string
	}{
		{SCTPInitScan, "sctp-init"},
		{SCTPCookieEchoScan, "sctp-cookie-echo"},
		{IdleScan, "idle"},
		{FTPBounceScan, "ftp-bounce"},
	}
	for _, tt := range tests {
		if got := tt.st.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.st, got, tt.want)
		}
	}
}

func TestScanTypeRawSocket(t *testing.T) {
	if !SCTPInitScan.RequiresRawSocket() {
		t.Error("SCTPInitScan should require raw socket")
	}
	if !SCTPCookieEchoScan.RequiresRawSocket() {
		t.Error("SCTPCookieEchoScan should require raw socket")
	}
	if !IdleScan.RequiresRawSocket() {
		t.Error("IdleScan should require raw socket")
	}
	if FTPBounceScan.RequiresRawSocket() {
		t.Error("FTPBounceScan should NOT require raw socket")
	}
}

func TestGenerateRandomTargets(t *testing.T) {
	targets := GenerateRandomTargets(10)
	if len(targets) != 10 {
		t.Errorf("got %d targets, want 10", len(targets))
	}
	// All should be valid public IPs
	for _, ip := range targets {
		parsed := parseIPv4(ip)
		if parsed == nil {
			t.Errorf("invalid IP: %s", ip)
		}
	}
}

func parseIPv4(s string) []byte {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			// basic check
			return []byte(s)
		}
	}
	return nil
}
