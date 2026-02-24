package gomap

import (
	"sort"
	"strings"
)

// PortsByRatio returns all TCP ports with an open frequency >= ratio.
// Ratio values typically range from 0.0 to 1.0.
// For example, PortsByRatio(0.01) returns ports open in >= 1% of scans.
func PortsByRatio(ratio float64) []int {
	var ports []int
	for port, freq := range TCPPortFrequency {
		if freq >= ratio {
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	return ports
}

// ExcludePorts removes the specified ports from a port list.
// The exclude spec uses the same syntax as ParsePortRange:
// single ports, ranges, and protocol prefixes.
func ExcludePorts(ports []int, excludeSpec string) ([]int, error) {
	excluded, err := ParsePortRange(excludeSpec)
	if err != nil {
		return nil, err
	}
	excludeSet := make(map[int]bool, len(excluded))
	for _, p := range excluded {
		excludeSet[p] = true
	}

	var result []int
	for _, p := range ports {
		if !excludeSet[p] {
			result = append(result, p)
		}
	}
	return result, nil
}

// TopUDPPorts returns the top N most common UDP ports by frequency.
func TopUDPPorts(n int) []int {
	type pf struct {
		port int
		freq float64
	}

	var pfs []pf
	for port, freq := range UDPPortFrequency {
		if freq > 0 {
			pfs = append(pfs, pf{port, freq})
		}
	}

	sort.Slice(pfs, func(i, j int) bool {
		return pfs[i].freq > pfs[j].freq
	})

	if len(pfs) > n {
		pfs = pfs[:n]
	}

	result := make([]int, len(pfs))
	for i, p := range pfs {
		result[i] = p.port
	}
	return result
}

// ParseScanFlags parses a custom TCP flag specification.
// Accepts numeric values (e.g., "0x29") or flag characters:
// U=URG, A=ACK, P=PSH, R=RST, S=SYN, F=FIN.
// Matches nmap's --scanflags behavior.
func ParseScanFlags(spec string) (uint16, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, nil
	}

	// Try numeric
	if strings.HasPrefix(spec, "0x") || strings.HasPrefix(spec, "0X") {
		var val uint16
		for _, c := range spec[2:] {
			val <<= 4
			switch {
			case c >= '0' && c <= '9':
				val |= uint16(c - '0')
			case c >= 'a' && c <= 'f':
				val |= uint16(c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				val |= uint16(c - 'A' + 10)
			default:
				return 0, &InvalidFlagError{Flag: string(c)}
			}
		}
		return val & 0x3F, nil // mask to 6 TCP flags
	}

	// Parse flag characters
	var flags uint16
	for _, c := range strings.ToUpper(spec) {
		switch c {
		case 'U':
			flags |= 0x0020 // URG
		case 'A':
			flags |= 0x0010 // ACK
		case 'P':
			flags |= 0x0008 // PSH
		case 'R':
			flags |= 0x0004 // RST
		case 'S':
			flags |= 0x0002 // SYN
		case 'F':
			flags |= 0x0001 // FIN
		default:
			return 0, &InvalidFlagError{Flag: string(c)}
		}
	}
	return flags, nil
}

// InvalidFlagError is returned when an unknown flag character is encountered.
type InvalidFlagError struct {
	Flag string
}

func (e *InvalidFlagError) Error() string {
	return "unknown TCP flag: " + e.Flag
}
