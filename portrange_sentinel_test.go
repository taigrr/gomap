package gomap

import (
	"errors"
	"testing"
)

func TestParsePortRangeSentinelErrors(t *testing.T) {
	badSpecs := []string{
		"abc",     // not a number
		"0",       // out of range
		"99999",   // out of range
		"10-5",    // inverted range
		"",        // empty
		"abc-def", // non-numeric range
	}
	for _, spec := range badSpecs {
		_, err := ParsePortRange(spec)
		if err == nil {
			t.Errorf("ParsePortRange(%q): expected error", spec)
			continue
		}
		if !errors.Is(err, ErrInvalidPortSpec) {
			t.Errorf("ParsePortRange(%q): error %v should wrap ErrInvalidPortSpec", spec, err)
		}
	}
}

func TestExpandTargetsSentinelError(t *testing.T) {
	_, err := ExpandTargets([]string{"invalid/cidr"})
	if !errors.Is(err, ErrInvalidCIDR) {
		t.Errorf("expected ErrInvalidCIDR, got %v", err)
	}
}
