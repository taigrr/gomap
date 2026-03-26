package gomap

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadExcludesFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "excludes.txt")
	content := "192.168.1.1\n# skip this\n10.0.0.5\n"
	os.WriteFile(path, []byte(content), 0644)

	excludes, err := LoadExcludesFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(excludes) != 2 {
		t.Errorf("expected 2 excludes, got %d", len(excludes))
	}
}

func TestListScanWithDNS(t *testing.T) {
	results, err := ListScan([]string{"127.0.0.1"}, false)
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

func TestListScanHostname(t *testing.T) {
	results, err := ListScan([]string{"localhost"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1, got %d", len(results))
	}
	if results[0].Hostname != "localhost" {
		t.Errorf("Hostname = %q, want localhost", results[0].Hostname)
	}
	if results[0].IP == "(unresolved)" {
		t.Error("localhost should resolve")
	}
}

func TestListScanInvalidCIDR(t *testing.T) {
	_, err := ListScan([]string{"bad/cidr"}, true)
	if err == nil {
		t.Error("expected error for invalid CIDR in ListScan")
	}
}

func TestGenerateRandomTargetsValid(t *testing.T) {
	targets := GenerateRandomTargets(10)
	if len(targets) != 10 {
		t.Errorf("expected 10 targets, got %d", len(targets))
	}
	for _, target := range targets {
		if net.ParseIP(target) == nil {
			t.Errorf("invalid IP: %s", target)
		}
	}
}

func TestListScanUnresolvable(t *testing.T) {
	results, err := ListScan([]string{"this-host-does-not-exist-abc123xyz.invalid"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1, got %d", len(results))
	}
	if results[0].IP != "(unresolved)" {
		t.Errorf("expected (unresolved), got %q", results[0].IP)
	}
}
