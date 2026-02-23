package gomap

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
)

// DecoyConfig configures decoy scanning.
// Decoys send scan packets from spoofed source IPs to make it harder
// to determine the real scanning host.
type DecoyConfig struct {
	// Decoys is a list of decoy IP addresses. Use "RND" to generate
	// a random IP, or "ME" to insert the real IP at that position.
	// Example: ["RND", "RND", "ME", "RND"]
	Decoys []string

	// resolved holds the final list of IPs after expanding RND/ME.
	resolved []net.IP
}

// ParseDecoys parses an nmap-style decoy string: "decoy1,decoy2,ME,RND"
func ParseDecoys(spec string, realIP string) (*DecoyConfig, error) {
	parts := strings.Split(spec, ",")
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty decoy specification")
	}

	dc := &DecoyConfig{Decoys: parts}
	hasME := false

	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch strings.ToUpper(part) {
		case "ME":
			ip := net.ParseIP(realIP)
			if ip == nil {
				return nil, fmt.Errorf("invalid real IP: %s", realIP)
			}
			dc.resolved = append(dc.resolved, ip)
			hasME = true
		case "RND":
			ip := randomPublicIP()
			dc.resolved = append(dc.resolved, ip)
		default:
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("invalid decoy IP: %s", part)
			}
			dc.resolved = append(dc.resolved, ip)
		}
	}

	// If ME wasn't specified, append real IP at the end
	if !hasME {
		ip := net.ParseIP(realIP)
		if ip != nil {
			dc.resolved = append(dc.resolved, ip)
		}
	}

	return dc, nil
}

// ResolvedIPs returns the final list of IPs (decoys + real) in order.
func (dc *DecoyConfig) ResolvedIPs() []net.IP {
	if dc == nil {
		return nil
	}
	return dc.resolved
}

// randomPublicIP generates a random routable IPv4 address,
// avoiding private, loopback, multicast, and reserved ranges.
func randomPublicIP() net.IP {
	for {
		b := make([]byte, 4)
		rand.Read(b)

		ip := net.IPv4(b[0], b[1], b[2], b[3])
		if isPublicIP(ip) {
			return ip
		}
	}
}

// randomPublicIPv6 generates a random global unicast IPv6 address.
func randomPublicIPv6() net.IP {
	b := make([]byte, 16)
	// Use 2001:db8 documentation prefix area but with random suffix
	// Actually use 2000::/3 global unicast range
	rand.Read(b)
	b[0] = 0x20 | (b[0] & 0x0f) // Ensure starts with 2xxx (global unicast)
	return net.IP(b)
}

func isPublicIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	// Skip private ranges
	privateRanges := []struct {
		start, end byte
	}{
		{10, 10},   // 10.0.0.0/8
		{127, 127}, // 127.0.0.0/8
		{169, 169}, // 169.254.0.0/16 (check second byte too)
		{224, 255}, // Multicast + reserved
	}

	first := ip4[0]
	for _, r := range privateRanges {
		if first >= r.start && first <= r.end {
			return false
		}
	}

	// 172.16.0.0/12
	if first == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return false
	}

	// 192.168.0.0/16
	if first == 192 && ip4[1] == 168 {
		return false
	}

	// 0.0.0.0/8
	if first == 0 {
		return false
	}

	return true
}

// GenerateRandomDecoys creates n random decoy IPs with the real IP
// inserted at a random position.
func GenerateRandomDecoys(n int, realIP string, ipv6 bool) (*DecoyConfig, error) {
	ip := net.ParseIP(realIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid real IP: %s", realIP)
	}

	dc := &DecoyConfig{}

	// Pick a random position for the real IP
	posN, _ := rand.Int(rand.Reader, big.NewInt(int64(n+1)))
	pos := int(posN.Int64())

	for i := 0; i <= n; i++ {
		if i == pos {
			dc.resolved = append(dc.resolved, ip)
			dc.Decoys = append(dc.Decoys, "ME")
		} else {
			var decoyIP net.IP
			if ipv6 {
				decoyIP = randomPublicIPv6()
			} else {
				decoyIP = randomPublicIP()
			}
			dc.resolved = append(dc.resolved, decoyIP)
			dc.Decoys = append(dc.Decoys, decoyIP.String())
		}
	}

	return dc, nil
}
