package gomap

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DiscoveryMethod represents a host discovery technique.
type DiscoveryMethod int

const (
	// DiscoveryTCPSYN sends a TCP SYN packet to detect hosts.
	// Default probe port is 80.
	DiscoveryTCPSYN DiscoveryMethod = iota

	// DiscoveryTCPACK sends a TCP ACK packet to detect hosts.
	// Default probe port is 80.
	DiscoveryTCPACK

	// DiscoveryUDP sends a UDP packet to detect hosts.
	// Default probe port is 40125.
	DiscoveryUDP

	// DiscoveryICMP sends an ICMP echo request (ping).
	DiscoveryICMP

	// DiscoveryConnect performs a TCP connect to detect hosts.
	// Works without privileges.
	DiscoveryConnect

	// DiscoveryARP uses ARP requests for local network discovery.
	// Only works on the local subnet.
	DiscoveryARP

	// DiscoveryICMPTimestamp sends an ICMP timestamp request.
	DiscoveryICMPTimestamp

	// DiscoveryICMPNetmask sends an ICMP address mask request.
	DiscoveryICMPNetmask

	// DiscoverySCTPInit sends an SCTP INIT chunk to detect hosts (-PY).
	DiscoverySCTPInit

	// DiscoveryIPProtocol sends raw IP packets with varying protocol numbers (-PO).
	DiscoveryIPProtocol
)

// DiscoveryOptions configures host discovery.
type DiscoveryOptions struct {
	// Methods specifies which discovery techniques to use.
	// If empty, defaults to [DiscoveryICMP, DiscoveryTCPSYN].
	Methods []DiscoveryMethod

	// Ports specifies TCP/UDP probe ports for non-ICMP methods.
	// Default: [80, 443] for TCP, [40125] for UDP.
	Ports []int

	// Timeout is the per-probe timeout (default 2s).
	Timeout time.Duration

	// Workers is the number of concurrent discovery goroutines (default 100).
	Workers int
}

func (o *DiscoveryOptions) defaults() {
	if len(o.Methods) == 0 {
		o.Methods = []DiscoveryMethod{DiscoveryICMP, DiscoveryConnect}
	}
	if len(o.Ports) == 0 {
		o.Ports = []int{80, 443}
	}
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	if o.Workers == 0 {
		o.Workers = 100
	}
}

// HostResult represents the discovery result for a single host.
type HostResult struct {
	IP       string
	Hostname string
	Alive    bool
	Method   DiscoveryMethod
	Latency  time.Duration
}

// DiscoverHosts probes a list of IP addresses to determine which are alive.
func DiscoverHosts(ctx context.Context, hosts []string, opts DiscoveryOptions) ([]HostResult, error) {
	opts.defaults()

	in := make(chan string, len(hosts))
	resultCh := make(chan HostResult, len(hosts))

	go func() {
		for _, h := range hosts {
			select {
			case in <- h:
			case <-ctx.Done():
				close(in)
				return
			}
		}
		close(in)
	}()

	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range in {
				if ctx.Err() != nil {
					return
				}
				result := probeHost(ctx, host, opts)
				resultCh <- result
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var results []HostResult
	for r := range resultCh {
		results = append(results, r)
	}

	return results, nil
}

// DiscoverHostsStream streams discovery results over a channel.
// The channel is closed when discovery completes.
func DiscoverHostsStream(ctx context.Context, hosts []string, opts DiscoveryOptions) <-chan HostResult {
	opts.defaults()
	out := make(chan HostResult, 64)

	go func() {
		defer close(out)

		in := make(chan string, len(hosts))
		go func() {
			for _, h := range hosts {
				select {
				case in <- h:
				case <-ctx.Done():
					close(in)
					return
				}
			}
			close(in)
		}()

		var wg sync.WaitGroup
		for i := 0; i < opts.Workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for host := range in {
					if ctx.Err() != nil {
						return
					}
					result := probeHost(ctx, host, opts)
					select {
					case out <- result:
					case <-ctx.Done():
						return
					}
				}
			}()
		}
		wg.Wait()
	}()

	return out
}

// DiscoverCIDR discovers all alive hosts in a CIDR range.
func DiscoverCIDR(ctx context.Context, cidr string, opts DiscoveryOptions) ([]HostResult, error) {
	hosts := CreateHostRange(cidr)
	if hosts == nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidCIDR, cidr)
	}
	return DiscoverHosts(ctx, hosts, opts)
}

// DiscoverLocal discovers alive hosts on the local network.
func DiscoverLocal(ctx context.Context, opts DiscoveryOptions) ([]HostResult, error) {
	cidr := GetLocalRange()
	return DiscoverCIDR(ctx, cidr, opts)
}

// probeHost tries each discovery method until one succeeds.
func probeHost(ctx context.Context, host string, opts DiscoveryOptions) HostResult {
	result := HostResult{IP: host}

	// Try reverse DNS (non-blocking, best-effort)
	names, err := net.LookupAddr(host)
	if err == nil && len(names) > 0 {
		result.Hostname = names[0]
	}

	for _, method := range opts.Methods {
		if ctx.Err() != nil {
			return result
		}

		start := time.Now()
		alive := false

		switch method {
		case DiscoveryICMP:
			alive = probeICMP(ctx, host, opts.Timeout)
		case DiscoveryConnect:
			alive = probeTCPConnect(ctx, host, opts.Ports, opts.Timeout)
		case DiscoveryTCPSYN:
			alive = probeTCPSYN(ctx, host, opts.Ports, opts.Timeout)
		case DiscoveryTCPACK:
			alive = probeTCPACK(ctx, host, opts.Ports, opts.Timeout)
		case DiscoveryUDP:
			alive = probeUDP(ctx, host, opts.Ports, opts.Timeout)
		case DiscoveryARP:
			alive = probeARP(ctx, host, opts.Timeout)
		case DiscoveryICMPTimestamp:
			alive = probeICMPTimestamp(ctx, host, opts.Timeout)
		case DiscoveryICMPNetmask:
			alive = probeICMPNetmask(ctx, host, opts.Timeout)
		case DiscoverySCTPInit:
			alive = probeSCTPInit(ctx, host, opts.Ports, opts.Timeout)
		case DiscoveryIPProtocol:
			alive = probeIPProtocol(ctx, host, nil, opts.Timeout)
		}

		if alive {
			result.Alive = true
			result.Method = method
			result.Latency = time.Since(start)
			return result
		}
	}

	return result
}

// probeTCPConnect attempts a TCP connect to any of the specified ports.
func probeTCPConnect(ctx context.Context, host string, ports []int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	for _, port := range ports {
		if ctx.Err() != nil {
			return false
		}
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return true
		}
		// Connection refused also means the host is alive
		if isConnectionRefused(err) {
			return true
		}
	}
	return false
}

// probeUDP sends UDP packets to detect hosts via ICMP unreachable.
func probeUDP(ctx context.Context, host string, ports []int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	for _, port := range ports {
		if ctx.Err() != nil {
			return false
		}
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := d.DialContext(ctx, "udp", addr)
		if err != nil {
			continue
		}
		conn.SetDeadline(time.Now().Add(timeout))
		_, err = conn.Write([]byte("\x00"))
		if err != nil {
			conn.Close()
			continue
		}
		buf := make([]byte, 128)
		_, err = conn.Read(buf)
		conn.Close()
		if err == nil {
			// Got a response = alive
			return true
		}
		// ICMP port unreachable also means alive
		if isConnectionRefused(err) {
			return true
		}
	}
	return false
}

// isConnectionRefused checks if an error indicates a connection refused (RST/ICMP unreachable).
func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	if opErr, ok := err.(*net.OpError); ok {
		if sysErr, ok := opErr.Err.(*net.OpError); ok {
			return sysErr.Err.Error() == "connect: connection refused"
		}
		return opErr.Err.Error() == "connect: connection refused"
	}
	// Check the error string as fallback
	return strings.Contains(err.Error(), "connection refused")
}
