package gomap

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// GetLocalIP returns the first non-loopback IPv4 address.
func GetLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no IPv4 address found")
}

// GetLocalRange returns the local /24 CIDR range, or defaults to 192.168.1.0/24.
func GetLocalRange() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "192.168.1.0/24"
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				split := strings.Split(ipnet.IP.String(), ".")
				return split[0] + "." + split[1] + "." + split[2] + ".0/24"
			}
		}
	}
	return "192.168.1.0/24"
}

// CreateHostRange converts a CIDR notation string to a slice of host IP strings.
func CreateHostRange(cidr string) []string {
	_, ipv4Net, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	finish := (start & mask) | (mask ^ 0xffffffff)

	var hosts []string
	for i := start + 1; i <= finish-1; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		hosts = append(hosts, ip.String())
	}

	return hosts
}

func canSocketBind(laddr string) bool {
	listenAddr, err := net.ResolveIPAddr("ip4", laddr)
	if err != nil {
		return false
	}

	conn, err := net.ListenIP("ip4:tcp", listenAddr)
	if err != nil {
		return false
	}

	conn.Close()
	return true
}
