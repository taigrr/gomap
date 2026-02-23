package gomap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTargetsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	content := "192.168.1.1\n# comment\n\n10.0.0.0/30\nexample.com\n"
	os.WriteFile(path, []byte(content), 0644)

	targets, err := LoadTargetsFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 {
		t.Errorf("expected 3 targets, got %d: %v", len(targets), targets)
	}
	if targets[0] != "192.168.1.1" {
		t.Errorf("first target = %q", targets[0])
	}
	if targets[1] != "10.0.0.0/30" {
		t.Errorf("second target = %q", targets[1])
	}
}

func TestLoadTargetsFromFileMissing(t *testing.T) {
	_, err := LoadTargetsFromFile("/nonexistent")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestExpandTargets(t *testing.T) {
	expanded, err := ExpandTargets([]string{"192.168.1.1", "10.0.0.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	// 1 IP + 2 hosts from /30
	if len(expanded) != 3 {
		t.Errorf("expected 3, got %d: %v", len(expanded), expanded)
	}
}

func TestExpandTargetsInvalidCIDR(t *testing.T) {
	_, err := ExpandTargets([]string{"invalid/cidr"})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestListScan(t *testing.T) {
	results, err := ListScan([]string{"127.0.0.1"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1, got %d", len(results))
	}
	if results[0].IP != "127.0.0.1" {
		t.Errorf("IP = %q", results[0].IP)
	}
}

func TestMaimonScanType(t *testing.T) {
	if MaimonScan.String() != "maimon" {
		t.Errorf("MaimonScan.String() = %q", MaimonScan.String())
	}
	if !MaimonScan.RequiresRawSocket() {
		t.Error("MaimonScan should require raw socket")
	}
}
