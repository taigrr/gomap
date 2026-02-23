// Package probedb parses and provides access to nmap-compatible service probe
// and OS fingerprint databases.
//
// The databases can be loaded from files at runtime or embedded at compile time
// using go:embed. This package handles both nmap-service-probes (for service/
// version detection) and nmap-os-db (for OS fingerprinting).
//
// File formats are documented at:
//   - https://nmap.org/book/vscan-fileformat.html (service probes)
//   - https://nmap.org/book/osdetect-fingerprint-format.html (OS fingerprints)
package probedb

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ServiceProbeDB is a parsed collection of service probes.
type ServiceProbeDB struct {
	// Probes ordered by protocol (TCP first, then UDP).
	Probes []ServiceProbe

	// ExcludePorts lists ports excluded from probing.
	ExcludePorts PortSet
}

// ServiceProbe represents a single probe definition from nmap-service-probes.
type ServiceProbe struct {
	// Name is the probe's identifier (e.g., "NULL", "GetRequest", "SSLSessionReq").
	Name string

	// Protocol is "TCP" or "UDP".
	Protocol string

	// ProbeString is the raw bytes to send (decoded from the q|...| format).
	ProbeString []byte

	// Rarity is 1-9, with 1 being the most common. Used to prioritize probes.
	Rarity int

	// Ports is the set of ports this probe should be sent to.
	Ports PortSet

	// SSLPorts is the set of ports that should use TLS before probing.
	SSLPorts PortSet

	// TotalWaitMS is the maximum time to wait for a response in milliseconds.
	TotalWaitMS int

	// TCPWrappedMS is the time to wait for tcpwrapped detection.
	TCPWrappedMS int

	// Fallback is the name of a probe to fall back to if no match is found.
	Fallback string

	// Matches are the patterns to match against responses.
	Matches []ServiceMatch

	// SoftMatches are lower-confidence patterns that don't terminate matching.
	SoftMatches []ServiceMatch
}

// ServiceMatch represents a single match or softmatch line.
type ServiceMatch struct {
	// Service is the service name (e.g., "ssh", "http", "mysql").
	Service string

	// Pattern is the compiled regex pattern.
	Pattern *regexp.Regexp

	// PatternStr is the original pattern string (for serialization).
	PatternStr string

	// Flags contains regex flags (s for DOTALL, i for case-insensitive).
	Flags string

	// VersionInfo contains extraction templates.
	VersionInfo VersionInfo
}

// VersionInfo contains the version extraction templates from a match line.
// Fields use $1, $2 etc. for regex group substitution.
type VersionInfo struct {
	// ProductName (p/.../)
	ProductName string

	// Version (v/.../)
	Version string

	// Info (i/.../)
	Info string

	// Hostname (h/.../)
	Hostname string

	// OS (o/.../)
	OS string

	// DeviceType (d/.../)
	DeviceType string

	// CPE entries (cpe:/.../)
	CPE []string
}

// Apply substitutes regex match groups into the version info templates.
func (v VersionInfo) Apply(submatches []string) VersionInfo {
	result := VersionInfo{
		ProductName: substituteGroups(v.ProductName, submatches),
		Version:     substituteGroups(v.Version, submatches),
		Info:        substituteGroups(v.Info, submatches),
		Hostname:    substituteGroups(v.Hostname, submatches),
		OS:          substituteGroups(v.OS, submatches),
		DeviceType:  substituteGroups(v.DeviceType, submatches),
	}
	for _, cpe := range v.CPE {
		result.CPE = append(result.CPE, substituteGroups(cpe, submatches))
	}
	return result
}

func substituteGroups(template string, groups []string) string {
	if template == "" {
		return ""
	}
	result := template
	for i := len(groups) - 1; i >= 1; i-- {
		result = strings.ReplaceAll(result, fmt.Sprintf("$%d", i), groups[i])
	}
	return result
}

// PortSet represents a set of port numbers, efficiently stored.
type PortSet struct {
	ports map[int]bool
}

// NewPortSet creates a PortSet from a comma-separated port specification.
// Supports individual ports (80) and ranges (1024-65535).
func NewPortSet(spec string) PortSet {
	ps := PortSet{ports: make(map[int]bool)}
	if spec == "" {
		return ps
	}

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, err1 := strconv.Atoi(rangeParts[0])
			end, err2 := strconv.Atoi(rangeParts[1])
			if err1 == nil && err2 == nil {
				for p := start; p <= end; p++ {
					ps.ports[p] = true
				}
			}
		} else {
			if p, err := strconv.Atoi(part); err == nil {
				ps.ports[p] = true
			}
		}
	}
	return ps
}

// Contains returns true if the port is in the set.
func (ps PortSet) Contains(port int) bool {
	return ps.ports[port]
}

// Len returns the number of ports in the set.
func (ps PortSet) Len() int {
	return len(ps.ports)
}

// Sorted returns all ports in the set in ascending order.
func (ps PortSet) Sorted() []int {
	ports := make([]int, 0, len(ps.ports))
	for p := range ps.ports {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// ParseServiceProbes parses an nmap-service-probes format file.
func ParseServiceProbes(r io.Reader) (*ServiceProbeDB, error) {
	db := &ServiceProbeDB{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB lines

	var currentProbe *ServiceProbe

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and blank lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		switch {
		case strings.HasPrefix(line, "Exclude "):
			spec := strings.TrimPrefix(line, "Exclude ")
			// Parse T: and U: prefixed port specs
			spec = strings.TrimPrefix(spec, "T:")
			spec = strings.TrimPrefix(spec, "U:")
			db.ExcludePorts = NewPortSet(spec)

		case strings.HasPrefix(line, "Probe "):
			// Save previous probe
			if currentProbe != nil {
				db.Probes = append(db.Probes, *currentProbe)
			}
			probe, err := parseProbe(line)
			if err != nil {
				continue // skip malformed probes
			}
			currentProbe = probe

		case strings.HasPrefix(line, "match "):
			if currentProbe == nil {
				continue
			}
			m, err := parseMatch(line[6:], false)
			if err != nil {
				continue
			}
			currentProbe.Matches = append(currentProbe.Matches, m)

		case strings.HasPrefix(line, "softmatch "):
			if currentProbe == nil {
				continue
			}
			m, err := parseMatch(line[10:], true)
			if err != nil {
				continue
			}
			currentProbe.SoftMatches = append(currentProbe.SoftMatches, m)

		case strings.HasPrefix(line, "ports "):
			if currentProbe != nil {
				currentProbe.Ports = NewPortSet(line[6:])
			}

		case strings.HasPrefix(line, "sslports "):
			if currentProbe != nil {
				currentProbe.SSLPorts = NewPortSet(line[9:])
			}

		case strings.HasPrefix(line, "totalwaitms "):
			if currentProbe != nil {
				currentProbe.TotalWaitMS, _ = strconv.Atoi(line[12:])
			}

		case strings.HasPrefix(line, "tcpwrappedms "):
			if currentProbe != nil {
				currentProbe.TCPWrappedMS, _ = strconv.Atoi(line[13:])
			}

		case strings.HasPrefix(line, "rarity "):
			if currentProbe != nil {
				currentProbe.Rarity, _ = strconv.Atoi(line[7:])
			}

		case strings.HasPrefix(line, "fallback "):
			if currentProbe != nil {
				currentProbe.Fallback = line[9:]
			}
		}
	}

	// Don't forget the last probe
	if currentProbe != nil {
		db.Probes = append(db.Probes, *currentProbe)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning service probes: %w", err)
	}

	return db, nil
}

// parseProbe parses a "Probe TCP|UDP name q|payload|" line.
func parseProbe(line string) (*ServiceProbe, error) {
	// Probe TCP NULL q||
	parts := strings.SplitN(line, " ", 4)
	if len(parts) < 4 {
		return nil, fmt.Errorf("malformed probe line: %s", line)
	}

	protocol := parts[1]
	name := parts[2]
	probeStr := parts[3]

	// Parse q|payload| format
	payload, err := parseProbeString(probeStr)
	if err != nil {
		return nil, err
	}

	return &ServiceProbe{
		Name:        name,
		Protocol:    protocol,
		ProbeString: payload,
		Rarity:      5, // default
		TotalWaitMS: 5000,
	}, nil
}

// parseProbeString decodes the q|...| probe string format.
// Handles \x hex escapes, \r, \n, \t, \\, \0, \a.
func parseProbeString(s string) ([]byte, error) {
	if len(s) < 3 || s[0] != 'q' {
		return nil, fmt.Errorf("invalid probe string format: %s", s)
	}

	delim := s[1]
	end := strings.LastIndexByte(s, delim)
	if end <= 1 {
		return nil, fmt.Errorf("unterminated probe string: %s", s)
	}

	raw := s[2:end]
	return decodeEscapes(raw), nil
}

// decodeEscapes processes C-style escape sequences in probe strings.
func decodeEscapes(s string) []byte {
	var result []byte
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'x':
				if i+3 < len(s) {
					b, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
					if err == nil {
						result = append(result, byte(b))
						i += 4
						continue
					}
				}
			case 'n':
				result = append(result, '\n')
				i += 2
				continue
			case 'r':
				result = append(result, '\r')
				i += 2
				continue
			case 't':
				result = append(result, '\t')
				i += 2
				continue
			case '\\':
				result = append(result, '\\')
				i += 2
				continue
			case '0':
				result = append(result, 0)
				i += 2
				continue
			case 'a':
				result = append(result, '\a')
				i += 2
				continue
			}
		}
		result = append(result, s[i])
		i++
	}
	return result
}

// parseMatch parses a match/softmatch line.
// Format: service m|pattern|flags [p/product/] [v/version/] [i/info/] [h/host/] [o/os/] [d/device/] [cpe:/cpe/]
func parseMatch(line string, soft bool) (ServiceMatch, error) {
	var m ServiceMatch

	// Extract service name
	spaceIdx := strings.IndexByte(line, ' ')
	if spaceIdx < 0 {
		return m, fmt.Errorf("no space in match line")
	}
	m.Service = line[:spaceIdx]
	rest := line[spaceIdx+1:]

	// Extract pattern: m|...|flags
	if len(rest) < 2 || rest[0] != 'm' {
		return m, fmt.Errorf("no pattern in match line")
	}

	delim := rest[1]
	// Find closing delimiter (handle escaped delimiters)
	patEnd := findClosingDelim(rest[2:], delim)
	if patEnd < 0 {
		return m, fmt.Errorf("unterminated pattern")
	}

	m.PatternStr = rest[2 : 2+patEnd]

	// Flags are between closing delim and next space
	flagStart := 2 + patEnd + 1
	flagEnd := flagStart
	for flagEnd < len(rest) && rest[flagEnd] != ' ' {
		flagEnd++
	}
	if flagStart < len(rest) {
		m.Flags = rest[flagStart:flagEnd]
	}

	// Compile regex
	reFlags := "(?s" // always enable . matches newline by default for binary
	if strings.Contains(m.Flags, "i") {
		reFlags += "i"
	}
	reFlags += ")"

	compiled, err := regexp.Compile(reFlags + m.PatternStr)
	if err != nil {
		return m, fmt.Errorf("compiling pattern: %w", err)
	}
	m.Pattern = compiled

	// Parse version info fields
	if flagEnd < len(rest) {
		m.VersionInfo = parseVersionInfo(rest[flagEnd:])
	}

	return m, nil
}

// findClosingDelim finds the index of the closing delimiter, handling backslash escapes.
func findClosingDelim(s string, delim byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++ // skip next char
			continue
		}
		if s[i] == delim {
			return i
		}
	}
	return -1
}

// parseVersionInfo extracts p/, v/, i/, h/, o/, d/, cpe:/ fields.
func parseVersionInfo(s string) VersionInfo {
	var vi VersionInfo

	extractField := func(prefix string) string {
		idx := strings.Index(s, prefix)
		if idx < 0 {
			return ""
		}
		start := idx + len(prefix)
		// Find closing /
		end := findClosingDelim(s[start:], '/')
		if end < 0 {
			return ""
		}
		return s[start : start+end]
	}

	vi.ProductName = extractField(" p/")
	vi.Version = extractField(" v/")
	vi.Info = extractField(" i/")
	vi.Hostname = extractField(" h/")
	vi.OS = extractField(" o/")
	vi.DeviceType = extractField(" d/")

	// Extract all CPE entries
	remaining := s
	for {
		idx := strings.Index(remaining, " cpe:/")
		if idx < 0 {
			break
		}
		start := idx + 6 // len(" cpe:/")
		end := findClosingDelim(remaining[start:], '/')
		if end < 0 {
			break
		}
		vi.CPE = append(vi.CPE, "cpe:/"+remaining[start:start+end])
		remaining = remaining[start+end:]
	}

	return vi
}

// ProbesForPort returns all probes applicable to a given port and protocol.
// Results are sorted by rarity (most common first).
func (db *ServiceProbeDB) ProbesForPort(port int, protocol string) []ServiceProbe {
	if db.ExcludePorts.Contains(port) {
		return nil
	}

	var result []ServiceProbe

	// NULL probe always first (for TCP)
	for i := range db.Probes {
		p := &db.Probes[i]
		if p.Protocol != protocol {
			continue
		}
		if p.Name == "NULL" {
			result = append(result, *p)
			break
		}
	}

	// Then probes whose port list includes this port, sorted by rarity
	for i := range db.Probes {
		p := &db.Probes[i]
		if p.Protocol != protocol || p.Name == "NULL" {
			continue
		}
		if p.Ports.Contains(port) || p.SSLPorts.Contains(port) {
			result = append(result, *p)
		}
	}

	return result
}
