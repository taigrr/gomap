package gomap

import (
	"reflect"
	"testing"
)

func TestTopUDPPortsNonPositive(t *testing.T) {
	for _, count := range []int{0, -1, -100} {
		if ports := TopUDPPorts(count); len(ports) != 0 {
			t.Errorf("TopUDPPorts(%d) = %v, want empty", count, ports)
		}
	}
}

func TestTopUDPPortsFrequencyTies(t *testing.T) {
	original := UDPPortFrequency
	UDPPortFrequency = map[int]float64{53: 0.5, 123: 0.25, 161: 0.25, 500: 0.25, 999: 0}
	t.Cleanup(func() { UDPPortFrequency = original })
	for range 100 {
		if got := TopUDPPorts(3); !reflect.DeepEqual(got, []int{53, 123, 161}) {
			t.Fatalf("TopUDPPorts(3) = %v, want [53 123 161]", got)
		}
	}
	if got := TopUDPPorts(100); !reflect.DeepEqual(got, []int{53, 123, 161, 500}) {
		t.Fatalf("TopUDPPorts(100) = %v, want all positive-frequency ports in order", got)
	}
}
