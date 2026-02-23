//go:build linux

package gomap

import (
	"testing"
)

func TestLoadARPTable(t *testing.T) {
	table, err := LoadARPTable()
	if err != nil {
		t.Skipf("Cannot load ARP table (may not have /proc/net/arp): %v", err)
	}
	for _, a := range table {
		t.Logf("%s", a)
	}
}

func TestParseARPEntry(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid entry",
			input:   "10.130.1.1       0x1         0x0         00:00:00:00:00:00     *        lo",
			wantErr: false,
		},
		{
			name:    "too few fields",
			input:   "10.130.1.1 0x1",
			wantErr: true,
		},
		{
			name:    "invalid MAC",
			input:   "10.130.1.1       0x1         0x0         ZZZZZZ     *        lo",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseARPEntry(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseARPEntry() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
