// Package gomap is a pure Go, cross-platform, library-importable port scanner
// inspired by nmap. It supports TCP connect scanning on all platforms and
// SYN (stealth) scanning on Linux where raw sockets are available.
package gomap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
)

// ScanResult contains the results of a scan on a single host.
type ScanResult struct {
	Hostname string
	IP       []net.IP
	Ports    []PortResult
}

// PortResult describes the state of a single port.
type PortResult struct {
	Port    int
	Open    bool
	State   PortState
	Service string
	Reason  string
}

// setStateReason is a helper to set state and reason together.
func (p *PortResult) setStateReason(state PortState, reason string) {
	p.State = state
	p.Reason = reason
	p.Open = state == PortOpen || state == PortOpenFiltered
}

// RangeScanResult contains results for multiple hosts.
type RangeScanResult []*ScanResult

// OpenPorts returns only the open ports from a scan result.
func (r *ScanResult) OpenPorts() []PortResult {
	var open []PortResult
	for _, p := range r.Ports {
		if p.Open {
			open = append(open, p)
		}
	}
	return open
}

// HasOpenPorts returns true if any ports are open.
func (r *ScanResult) HasOpenPorts() bool {
	for _, p := range r.Ports {
		if p.Open {
			return true
		}
	}
	return false
}

// String returns a human-readable summary of the scan result.
func (r *ScanResult) String() string {
	b := bytes.NewBuffer(nil)
	ip := r.IP[len(r.IP)-1]

	fmt.Fprintf(b, "\nHost: %s (%s)\n", r.Hostname, ip)

	if r.HasOpenPorts() {
		fmt.Fprintf(b, "\t|     %s\t%s\n", "Port", "Service")
		fmt.Fprintf(b, "\t|     %s\t%s\n", "----", "-------")
		for _, v := range r.Ports {
			if v.Open {
				fmt.Fprintf(b, "\t|---- %d\t%s\n", v.Port, v.Service)
			}
		}
	} else if r.Hostname != "Unknown" {
		fmt.Fprintf(b, "\t|---- %s\n", "No Open Ports Found")
	}
	return b.String()
}

// String returns a human-readable summary of all scan results.
func (results RangeScanResult) String() string {
	b := bytes.NewBuffer(nil)
	for _, r := range results {
		b.WriteString(r.String())
	}
	return b.String()
}

// JSONResult is the JSON-serializable representation of a single host scan.
type JSONResult struct {
	IP       string   `json:"ip"`
	Hostname string   `json:"hostname"`
	Active   bool     `json:"active"`
	Ports    []string `json:"ports,omitempty"`
}

// JSON returns a JSON-encoded string of the scan result.
func (r *ScanResult) JSON() (string, error) {
	jr := JSONResult{
		IP:       r.IP[len(r.IP)-1].String(),
		Hostname: r.Hostname,
		Active:   r.HasOpenPorts(),
	}

	for _, v := range r.Ports {
		if v.Open {
			jr.Ports = append(jr.Ports, fmt.Sprintf("%d: %s", v.Port, v.Service))
		}
	}

	j, err := json.MarshalIndent(jr, "", "\t")
	if err != nil {
		return "", err
	}
	return string(j), nil
}

// JSON returns a JSON-encoded string of all scan results.
func (results RangeScanResult) JSON() (string, error) {
	var jrs []JSONResult
	for _, r := range results {
		jr := JSONResult{
			IP:       r.IP[len(r.IP)-1].String(),
			Hostname: r.Hostname,
			Active:   r.HasOpenPorts(),
		}
		for _, v := range r.Ports {
			if v.Open {
				jr.Ports = append(jr.Ports, fmt.Sprintf("%d: %s", v.Port, v.Service))
			}
		}
		jrs = append(jrs, jr)
	}

	j, err := json.MarshalIndent(jrs, "", "\t")
	if err != nil {
		return "", err
	}
	return string(j), nil
}
