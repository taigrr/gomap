//go:build !nonpsl

package gomap

import "testing"

func TestDefaultProbeDB(t *testing.T) {
	db, err := DefaultProbeDB()
	if err != nil {
		t.Fatalf("DefaultProbeDB error: %v", err)
	}
	if db == nil {
		t.Fatal("DefaultProbeDB returned nil")
	}
	if len(db.Probes) == 0 {
		t.Error("expected probes in embedded database")
	}
	t.Logf("Embedded probe DB: %d probes", len(db.Probes))

	found := false
	for _, p := range db.Probes {
		if p.Name == "NULL" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected NULL probe in database")
	}
}
