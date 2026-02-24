package gomap

import "testing"

func TestListInterfaces(t *testing.T) {
	ifaces, err := ListInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(ifaces) == 0 {
		t.Error("ListInterfaces should return at least one interface")
	}
	// Should have at least lo
	found := false
	for _, iface := range ifaces {
		if iface.Name == "lo" {
			found = true
		}
	}
	if !found {
		t.Log("warning: no loopback interface found (may be named differently)")
	}
}

func TestFormatInterfaceList(t *testing.T) {
	ifaces := []InterfaceInfo{
		{Name: "eth0", Index: 2, MTU: 1500, Flags: "up|broadcast", MAC: "aa:bb:cc:dd:ee:ff", Addrs: []string{"192.168.1.1/24"}},
	}
	out := FormatInterfaceList(ifaces)
	if out == "" {
		t.Error("FormatInterfaceList should produce output")
	}
}
