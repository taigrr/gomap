package gomap

import (
	"reflect"
	"testing"
)

func TestCreateHostRangeIPv4Boundaries(t *testing.T) {
	tests := []struct {
		cidr string
		want []string
	}{
		{"0.0.0.0/32", nil},
		{"255.255.255.255/32", nil},
		{"192.0.2.1/32", nil},
		{"0.0.0.0/31", nil},
		{"255.255.255.254/31", nil},
		{"0.0.0.0/30", []string{"0.0.0.1", "0.0.0.2"}},
		{"255.255.255.255/30", []string{"255.255.255.253", "255.255.255.254"}},
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			if got := CreateHostRange(tt.cidr); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("CreateHostRange(%q) = %v, want %v", tt.cidr, got, tt.want)
			}
		})
	}
}
