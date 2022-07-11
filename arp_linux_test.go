package gomap

import (
	"errors"
	"fmt"
	"testing"
)

func TestLoadArpTable(t *testing.T) {
	err := LoadArpTable()
	if err != nil {
		t.Errorf("Error loading Arp Table: %v", err)
	}
	for _, a := range arpTable {
		fmt.Println(a)
	}
}

func TestParseArpEntry(t *testing.T) {
	arpEntries := []struct {
		name     string
		input    string
		err      error
		arpEntry ArpEntry
	}{{name: "working line",
		input: "10.130.1.1       0x1         0x0         00:00:00:00:00:00     *        enp4s0",
		err:   nil,
	}, {name: "broken line",
		input: "10.130.1.1       0x1         0x0         00:00:00:00:00:00     *        enp4s0",
		err:   errors.New("asdasd"),
	},
	}

	for _, entry := range arpEntries {
		t.Run(entry.name, func(t *testing.T) {
			_, e := ParseArpEntry(entry.input)
			if e != entry.err {
				t.Errorf("Expected error %v, but got %v!", entry.err, e)
			}

		})

	}
}
