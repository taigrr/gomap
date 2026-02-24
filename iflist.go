package gomap

import (
	"fmt"
	"net"
	"strings"
)

// InterfaceInfo contains information about a network interface.
type InterfaceInfo struct {
	Name    string
	Index   int
	MTU     int
	Flags   string
	MAC     string
	Addrs   []string
}

// ListInterfaces returns information about all network interfaces,
// matching nmap's --iflist output.
func ListInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []InterfaceInfo
	for _, iface := range ifaces {
		info := InterfaceInfo{
			Name:  iface.Name,
			Index: iface.Index,
			MTU:   iface.MTU,
			Flags: iface.Flags.String(),
		}
		if iface.HardwareAddr != nil {
			info.MAC = iface.HardwareAddr.String()
		}
		addrs, err := iface.Addrs()
		if err == nil {
			for _, a := range addrs {
				info.Addrs = append(info.Addrs, a.String())
			}
		}
		result = append(result, info)
	}
	return result, nil
}

// FormatInterfaceList produces nmap-compatible --iflist output.
func FormatInterfaceList(ifaces []InterfaceInfo) string {
	var b strings.Builder

	b.WriteString("************************INTERFACES************************\n")
	fmt.Fprintf(&b, "%-5s %-16s %-18s %-6s %-8s %s\n", "DEV", "SHORT", "MAC", "MTU", "FLAGS", "ADDRESSES")

	for _, iface := range ifaces {
		addrs := strings.Join(iface.Addrs, " ")
		mac := iface.MAC
		if mac == "" {
			mac = "(none)"
		}
		fmt.Fprintf(&b, "%-5d %-16s %-18s %-6d %-8s %s\n",
			iface.Index, iface.Name, mac, iface.MTU, iface.Flags, addrs)
	}

	return b.String()
}
