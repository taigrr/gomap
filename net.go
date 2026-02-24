package gomap

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strings"
)

// GetLocalIP returns the first non-loopback IPv4 address.
func GetLocalIP() (string, error) {
	return getLocalIPByFamily(false)
}

// GetLocalIPv6 returns the first non-loopback IPv6 address.
func GetLocalIPv6() (string, error) {
	return getLocalIPByFamily(true)
}

// GetLocalAddr returns the local IP matching the target's address family.
// If target is IPv6, returns a local IPv6 address; otherwise IPv4.
func GetLocalAddr(target string) (string, error) {
	ip := net.ParseIP(target)
	if ip != nil && ip.To4() == nil {
		return GetLocalIPv6()
	}
	return GetLocalIP()
}

func getLocalIPByFamily(wantV6 bool) (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, address := range addrs {
		ipnet, ok := address.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		isV4 := ipnet.IP.To4() != nil
		if wantV6 && !isV4 && ipnet.IP.IsGlobalUnicast() {
			return ipnet.IP.String(), nil
		}
		if !wantV6 && isV4 {
			return ipnet.IP.String(), nil
		}
	}
	family := "IPv4"
	if wantV6 {
		family = "IPv6"
	}
	return "", fmt.Errorf("no %s address found", family)
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
// Supports both IPv4 and IPv6 CIDR ranges.
func CreateHostRange(cidr string) []string {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	// IPv4
	if ipNet.IP.To4() != nil {
		return createHostRangeV4(ipNet)
	}

	// IPv6
	return createHostRangeV6(ipNet)
}

func createHostRangeV4(ipNet *net.IPNet) []string {
	mask := binary.BigEndian.Uint32(ipNet.Mask)
	start := binary.BigEndian.Uint32(ipNet.IP.To4())
	finish := (start & mask) | (mask ^ 0xffffffff)

	var hosts []string
	for i := start + 1; i <= finish-1; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		hosts = append(hosts, ip.String())
	}
	return hosts
}

func createHostRangeV6(ipNet *net.IPNet) []string {
	// For IPv6, only enumerate if prefix is /120 or larger (256 hosts max)
	// to avoid generating billions of addresses.
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	if hostBits > 8 {
		// Too many hosts — return nil to signal the caller should
		// use a different discovery method.
		return nil
	}

	start := new(big.Int).SetBytes(ipNet.IP.To16())
	maskInt := new(big.Int).SetBytes(ipNet.Mask)
	notMask := new(big.Int).Not(maskInt)
	notMask.And(notMask, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)))
	finish := new(big.Int).Or(start, notMask)

	one := big.NewInt(1)
	current := new(big.Int).Add(start, one)
	end := new(big.Int).Sub(finish, one)

	var hosts []string
	for current.Cmp(end) <= 0 {
		ipBytes := current.Bytes()
		ip := make(net.IP, 16)
		copy(ip[16-len(ipBytes):], ipBytes)
		hosts = append(hosts, ip.String())
		current.Add(current, one)
	}
	return hosts
}

// IsIPv6 returns true if the address string is an IPv6 address.
func IsIPv6(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.To4() == nil
}

// ipProtocol returns the appropriate raw protocol string for the address family.
func ipProtocol(addr string, proto string) string {
	if IsIPv6(addr) {
		return "ip6:" + proto
	}
	return "ip4:" + proto
}

// selectIP picks the best IP from a list based on address family preference.
func selectIP(ips []net.IP, preferIPv6 bool) net.IP {
	for _, ip := range ips {
		isV4 := ip.To4() != nil
		if preferIPv6 && !isV4 {
			return ip
		}
		if !preferIPv6 && isV4 {
			return ip
		}
	}
	return ips[0] // fall back to first available
}

// defaultInterface returns the name of the network interface used for
// the default route. It finds the interface that has a non-loopback,
// globally-routable address.
func defaultInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() && ip.IsGlobalUnicast() {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no suitable network interface found")
}

func canSocketBind(laddr string) bool {
	proto := "ip4"
	if IsIPv6(laddr) {
		proto = "ip6"
	}
	listenAddr, err := net.ResolveIPAddr(proto, laddr)
	if err != nil {
		return false
	}

	conn, err := net.ListenIP(proto+":tcp", listenAddr)
	if err != nil {
		return false
	}

	conn.Close()
	return true
}
