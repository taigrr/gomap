package gomap

import (
	"fmt"
	"strconv"
	"strings"
)

// ParsePortRange parses an nmap-style port specification string.
// Supports:
//   - Single ports: "80"
//   - Ranges: "1-1024"
//   - Comma-separated: "80,443,8080"
//   - Mixed: "22,80-90,443,8000-9000"
//   - Protocol prefix: "T:80,U:53" (T=TCP, U=UDP)
//   - All ports: "-" (equivalent to "1-65535")
//   - Top ports: not handled here (use --top-ports flag)
func ParsePortRange(spec string) ([]int, error) {
	if spec == "-" {
		ports := make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
		return ports, nil
	}

	seen := make(map[int]bool)
	var ports []int

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Strip protocol prefix (T: or U:) — we handle protocol elsewhere
		if len(part) > 2 && part[1] == ':' {
			prefix := strings.ToUpper(part[:1])
			if prefix == "T" || prefix == "U" {
				part = part[2:]
			}
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("%w: invalid range start: %q", ErrInvalidPortSpec, rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("%w: invalid range end: %q", ErrInvalidPortSpec, rangeParts[1])
			}

			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("%w: invalid range: %d-%d", ErrInvalidPortSpec, start, end)
			}

			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid port: %q", ErrInvalidPortSpec, part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("%w: port out of range: %d", ErrInvalidPortSpec, p)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("%w: no ports specified", ErrInvalidPortSpec)
	}

	return ports, nil
}
