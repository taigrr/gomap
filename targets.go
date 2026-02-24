package gomap

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// LoadTargetsFromFile reads a list of targets (IPs, hostnames, CIDRs) from a file.
// One target per line. Empty lines and lines starting with # are skipped.
func LoadTargetsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening target file: %w", err)
	}
	defer f.Close()

	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading target file: %w", err)
	}

	return targets, nil
}

// LoadExcludesFromFile reads a list of exclude targets from a file.
// Same format as LoadTargetsFromFile.
func LoadExcludesFromFile(path string) ([]string, error) {
	return LoadTargetsFromFile(path)
}

// ExpandTargets takes a mixed list of IPs, hostnames, and CIDRs and
// expands CIDRs into individual IPs. Hostnames are resolved.
func ExpandTargets(targets []string) ([]string, error) {
	var expanded []string
	for _, t := range targets {
		if strings.Contains(t, "/") {
			hosts := CreateHostRange(t)
			if hosts == nil {
				return nil, fmt.Errorf("invalid CIDR: %s", t)
			}
			expanded = append(expanded, hosts...)
		} else {
			expanded = append(expanded, t)
		}
	}
	return expanded, nil
}

// ListTargets resolves and lists targets without scanning (nmap -sL).
// Returns resolved hostnames and IPs.
type ListTarget struct {
	Input    string
	IP       string
	Hostname string
}

// GenerateRandomTargets generates n random public IPv4 addresses.
// Equivalent to nmap -iR.
func GenerateRandomTargets(n int) []string {
	targets := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ip := randomPublicIP()
		targets = append(targets, ip.String())
	}
	return targets
}

// ListScan resolves targets and returns their IPs and hostnames without
// sending any packets to the targets (equivalent to nmap -sL).
func ListScan(targets []string, noDNS bool) ([]ListTarget, error) {
	var results []ListTarget

	expanded, err := ExpandTargets(targets)
	if err != nil {
		return nil, err
	}

	for _, t := range expanded {
		lt := ListTarget{Input: t}

		// Check if it's already an IP
		ip := net.ParseIP(t)
		if ip != nil {
			lt.IP = ip.String()
			if !noDNS {
				names, err := net.LookupAddr(lt.IP)
				if err == nil && len(names) > 0 {
					lt.Hostname = strings.TrimSuffix(names[0], ".")
				}
			}
		} else {
			// It's a hostname — resolve it
			lt.Hostname = t
			ips, err := net.LookupIP(t)
			if err != nil {
				lt.IP = "(unresolved)"
			} else if len(ips) > 0 {
				lt.IP = ips[0].String()
			}
		}

		results = append(results, lt)
	}

	return results, nil
}
