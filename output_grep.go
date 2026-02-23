package gomap

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ToGrepable converts a ScanResult to nmap's grepable output format (-oG).
// Format: Host: <ip> (<hostname>) Ports: <port>/<state>/<proto>//<service>///
func (r *ScanResult) ToGrepable() string {
	return formatGrepable([]*ScanResult{r})
}

// ToGrepable converts a RangeScanResult to grepable format.
func (results RangeScanResult) ToGrepable() string {
	return formatGrepable(results)
}

func formatGrepable(results []*ScanResult) string {
	var b strings.Builder

	// Header
	b.WriteString(fmt.Sprintf("# gomap grepable output - %s\n", time.Now().Format(time.RFC1123)))

	for _, r := range results {
		ip := ""
		if len(r.IP) > 0 {
			ip = r.IP[len(r.IP)-1].String()
		}

		hostname := r.Hostname
		if hostname == "Unknown" || hostname == "" {
			hostname = ""
		}

		// Sort ports
		sorted := make([]PortResult, len(r.Ports))
		copy(sorted, r.Ports)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Port < sorted[j].Port
		})

		// Build port strings
		var portStrs []string
		for _, p := range sorted {
			state := p.State.String()
			svc := p.Service
			if svc == "" || svc == "unknown" {
				svc = LookupService(p.Port)
			}

			// Format: port/state/protocol//service///
			portStrs = append(portStrs, fmt.Sprintf("%d/%s/tcp//%s///", p.Port, state, svc))
		}

		if hostname != "" {
			b.WriteString(fmt.Sprintf("Host: %s (%s)\tPorts: %s\n", ip, hostname, strings.Join(portStrs, ", ")))
		} else {
			b.WriteString(fmt.Sprintf("Host: %s ()\tPorts: %s\n", ip, strings.Join(portStrs, ", ")))
		}
	}

	return b.String()
}
