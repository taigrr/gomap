// Package gomap is a pure Go, cross-platform, library-importable port scanner
// inspired by nmap. It supports TCP connect scanning on all platforms and
// SYN (stealth) scanning on Linux where raw sockets are available.
package gomap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// ScanResult contains the results of a scan on a single host.
type ScanResult struct {
	Hostname  string
	IP        []net.IP
	Ports     []PortResult
	StartTime time.Time     // when scanning began for this host
	EndTime   time.Time     // when scanning completed
	Duration  time.Duration // total scan time for this host
}

// PortResult describes the state of a single port.
type PortResult struct {
	Port     int
	Protocol string // "tcp", "udp", or "sctp" (default "tcp")
	Open     bool
	State    PortState
	Service  string
	Reason   string
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
	buf := bytes.NewBuffer(nil)
	ipStr := "<unknown>"
	if len(r.IP) > 0 {
		ipStr = r.IP[len(r.IP)-1].String()
	}

	fmt.Fprintf(buf, "\nHost: %s (%s)\n", r.Hostname, ipStr)

	if r.HasOpenPorts() {
		fmt.Fprintf(buf, "\t|     %s\t%s\n", "Port", "Service")
		fmt.Fprintf(buf, "\t|     %s\t%s\n", "----", "-------")
		for _, v := range r.Ports {
			if v.Open {
				fmt.Fprintf(buf, "\t|---- %d\t%s\n", v.Port, v.Service)
			}
		}
	} else if r.Hostname != "Unknown" {
		fmt.Fprintf(buf, "\t|---- %s\n", "No Open Ports Found")
	}
	return buf.String()
}

// String returns a human-readable summary of all scan results.
func (results RangeScanResult) String() string {
	buf := bytes.NewBuffer(nil)
	for _, r := range results {
		buf.WriteString(r.String())
	}
	return buf.String()
}

// JSONResult is the JSON-serializable representation of a single host scan.
type JSONResult struct {
	IP        string     `json:"ip"`
	Hostname  string     `json:"hostname"`
	Active    bool       `json:"active"`
	StartTime string     `json:"start_time,omitempty"`
	EndTime   string     `json:"end_time,omitempty"`
	Duration  string     `json:"duration,omitempty"`
	Ports     []JSONPort `json:"ports,omitempty"`
}

// JSONPort is a structured representation of a port result for JSON output.
type JSONPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Reason   string `json:"reason,omitempty"`
}

// JSON returns a JSON-encoded string of the scan result.
func (r *ScanResult) JSON() (string, error) {
	jr := resultToJSON(r)
	j, err := json.MarshalIndent(jr, "", "\t")
	if err != nil {
		return "", err
	}
	return string(j), nil
}

// JSON returns a JSON-encoded string of all scan results.
func (results RangeScanResult) JSON() (string, error) {
	jrs := make([]JSONResult, 0, len(results))
	for _, r := range results {
		jrs = append(jrs, resultToJSON(r))
	}
	j, err := json.MarshalIndent(jrs, "", "\t")
	if err != nil {
		return "", err
	}
	return string(j), nil
}

func resultToJSON(r *ScanResult) JSONResult {
	ipStr := ""
	if len(r.IP) > 0 {
		ipStr = r.IP[len(r.IP)-1].String()
	}
	jr := JSONResult{
		IP:       ipStr,
		Hostname: r.Hostname,
		Active:   r.HasOpenPorts(),
	}
	if !r.StartTime.IsZero() {
		jr.StartTime = r.StartTime.Format(time.RFC3339)
	}
	if !r.EndTime.IsZero() {
		jr.EndTime = r.EndTime.Format(time.RFC3339)
	}
	if r.Duration > 0 {
		jr.Duration = r.Duration.String()
	}
	for _, v := range r.Ports {
		proto := v.Protocol
		if proto == "" {
			proto = "tcp"
		}
		jr.Ports = append(jr.Ports, JSONPort{
			Port:     v.Port,
			Protocol: proto,
			State:    v.State.String(),
			Service:  v.Service,
			Reason:   v.Reason,
		})
	}
	return jr
}
