package gomap

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// ScanOptions configures a scan.
type ScanOptions struct {
	// ScanType determines the scanning technique (default ConnectScan).
	ScanType ScanType

	// FastScan uses the common port list instead of the detailed list.
	FastScan bool

	// Stealth is a convenience alias that sets ScanType to SYNScan.
	// Deprecated: use ScanType directly.
	Stealth bool

	// Timeout is the per-port connection timeout (default 3s).
	Timeout time.Duration

	// Workers is the number of concurrent scanning goroutines (default auto).
	Workers int

	// ProgressFunc is called after each port is scanned.
	// It receives the number of ports scanned so far and the total.
	// Set to nil to disable progress reporting.
	ProgressFunc func(scanned, total int)

	// Ports specifies custom ports to scan. If nil, the default port list is used.
	Ports []int
}

func (o *ScanOptions) defaults() {
	// Handle Stealth backwards compat
	if o.Stealth && o.ScanType == ConnectScan {
		o.ScanType = SYNScan
	}
	if o.Timeout == 0 {
		o.Timeout = 3 * time.Second
	}
	if o.Workers == 0 {
		if o.FastScan {
			o.Workers = 50
		} else {
			o.Workers = 500
		}
	}
}

// protocol returns the appropriate network protocol string for the scan type.
func (o *ScanOptions) protocol() string {
	if o.ScanType == UDPScan {
		return "udp"
	}
	return "tcp"
}

// ScanHost scans a single host for open ports.
func ScanHost(ctx context.Context, hostname string, opts ScanOptions) (*ScanResult, error) {
	opts.defaults()

	laddr, err := GetLocalIP()
	if err != nil {
		return nil, fmt.Errorf("getting local IP: %w", err)
	}

	if opts.ScanType.RequiresRawSocket() {
		if !canSocketBind(laddr) {
			return nil, fmt.Errorf("socket: operation not permitted (raw socket required for %s scan)", opts.ScanType)
		}
	}
	return scanHostPorts(ctx, hostname, laddr, opts)
}

// ScanRange scans every address on the local CIDR for open ports.
func ScanRange(ctx context.Context, opts ScanOptions) (RangeScanResult, error) {
	opts.defaults()

	laddr, err := GetLocalIP()
	if err != nil {
		return nil, fmt.Errorf("getting local IP: %w", err)
	}

	if opts.ScanType.RequiresRawSocket() {
		if !canSocketBind(laddr) {
			return nil, fmt.Errorf("socket: operation not permitted (raw socket required for %s scan)", opts.ScanType)
		}
	}

	return scanRange(ctx, laddr, opts)
}

// ScanCIDR scans every address on a given CIDR for open ports.
func ScanCIDR(ctx context.Context, cidr string, opts ScanOptions) (RangeScanResult, error) {
	opts.defaults()

	laddr, err := GetLocalIP()
	if err != nil {
		return nil, fmt.Errorf("getting local IP: %w", err)
	}

	if opts.ScanType.RequiresRawSocket() {
		if !canSocketBind(laddr) {
			return nil, fmt.Errorf("socket: operation not permitted (raw socket required for %s scan)", opts.ScanType)
		}
	}

	hosts := CreateHostRange(cidr)
	var results RangeScanResult

	for _, h := range hosts {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		scan, err := scanHostPorts(ctx, h, laddr, opts)
		if err != nil {
			continue
		}
		results = append(results, scan)
	}

	return results, nil
}

func scanRange(ctx context.Context, laddr string, opts ScanOptions) (RangeScanResult, error) {
	iprange := GetLocalRange()
	hosts := CreateHostRange(iprange)

	var results RangeScanResult
	for _, h := range hosts {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		scan, err := scanHostPorts(ctx, h, laddr, opts)
		if err != nil {
			continue
		}
		results = append(results, scan)
	}

	return results, nil
}

func scanHostPorts(ctx context.Context, hostname, laddr string, opts ScanOptions) (*ScanResult, error) {
	// Resolve the host
	addr, err := net.LookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", hostname, err)
	}

	hname, err := net.LookupAddr(hostname)
	if opts.FastScan {
		if err != nil {
			return nil, fmt.Errorf("reverse lookup %s: %w", hostname, err)
		}
	} else if err != nil {
		hname = append(hname, "Unknown")
	}

	// Determine ports to scan
	var portList map[int]string
	if len(opts.Ports) > 0 {
		portList = make(map[int]string, len(opts.Ports))
		for _, p := range opts.Ports {
			svc := LookupService(p)
			portList[p] = svc
		}
	} else if opts.FastScan {
		portList = CommonPorts
	} else {
		portList = DetailedPorts
	}

	tasks := len(portList)
	in := make(chan portJob, tasks)
	resultCh := make(chan PortResult, tasks)

	// Feed jobs
	go func() {
		for port, service := range portList {
			select {
			case in <- portJob{port: port, service: service}:
			case <-ctx.Done():
				close(in)
				return
			}
		}
		close(in)
	}()

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range in {
				if ctx.Err() != nil {
					return
				}
				scanPort(ctx, resultCh, opts, hostname, laddr, job)
			}
		}()
	}

	// Close results when workers finish
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results
	var results []PortResult
	count := 0
	for result := range resultCh {
		results = append(results, result)
		count++
		if opts.ProgressFunc != nil {
			opts.ProgressFunc(count, tasks)
		}
	}

	return &ScanResult{
		Hostname: hname[0],
		IP:       addr,
		Ports:    results,
	}, nil
}

type portJob struct {
	port    int
	service string
}

// scanPort dispatches a port scan to the appropriate scanner based on scan type.
func scanPort(ctx context.Context, resultCh chan<- PortResult, opts ScanOptions, hostname, laddr string, job portJob) {
	switch opts.ScanType {
	case ConnectScan:
		scanPortConnect(ctx, resultCh, opts.protocol(), hostname, job.service, job.port, opts.Timeout)
	case SYNScan:
		scanPortSyn(ctx, resultCh, opts.protocol(), hostname, job.service, job.port, laddr, opts.Timeout)
	case FINScan:
		scanPortRaw(ctx, resultCh, hostname, job.service, job.port, laddr, tcpFIN, opts.Timeout)
	case XmasScan:
		scanPortRaw(ctx, resultCh, hostname, job.service, job.port, laddr, tcpFIN|tcpPSH|tcpURG, opts.Timeout)
	case NullScan:
		scanPortRaw(ctx, resultCh, hostname, job.service, job.port, laddr, 0, opts.Timeout)
	case ACKScan:
		scanPortACK(ctx, resultCh, hostname, job.service, job.port, laddr, opts.Timeout)
	case WindowScan:
		scanPortWindow(ctx, resultCh, hostname, job.service, job.port, laddr, opts.Timeout)
	case UDPScan:
		scanPortUDP(ctx, resultCh, hostname, job.service, job.port, opts.Timeout)
	default:
		scanPortConnect(ctx, resultCh, "tcp", hostname, job.service, job.port, opts.Timeout)
	}
}

// scanPortConnect performs a full TCP connect() scan on a single port.
func scanPortConnect(ctx context.Context, resultCh chan<- PortResult, protocol, hostname, service string, port int, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}

	// Use a dialer that respects context
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, protocol, net.JoinHostPort(hostname, strconv.Itoa(port)))
	if err != nil {
		if ctx.Err() != nil {
			result.State = PortFiltered
		} else {
			result.State = PortClosed
		}
		resultCh <- result
		return
	}
	conn.Close()
	result.Open = true
	result.State = PortOpen
	resultCh <- result
}

// scanPortUDP sends an empty UDP packet and listens for ICMP unreachable.
// No response = open|filtered, ICMP unreachable = closed.
func scanPortUDP(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(hostname, strconv.Itoa(port)))
	if err != nil {
		result.State = PortFiltered
		resultCh <- result
		return
	}
	defer conn.Close()

	// Send empty UDP packet
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}
	conn.SetDeadline(deadline)

	_, err = conn.Write([]byte{})
	if err != nil {
		result.State = PortFiltered
		resultCh <- result
		return
	}

	// Try to read response
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		if ctx.Err() != nil {
			result.State = PortFiltered
			resultCh <- result
			return
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.State = PortOpenFiltered
			result.Open = true
			resultCh <- result
			return
		}
		result.State = PortClosed
		resultCh <- result
		return
	}

	result.Open = true
	result.State = PortOpen
	resultCh <- result
}
