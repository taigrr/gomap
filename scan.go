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
	// Protocol is the network protocol to use (default "tcp").
	Protocol string

	// FastScan uses the common port list instead of the detailed list.
	FastScan bool

	// Stealth enables SYN scanning (Linux only, requires raw socket privileges).
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
	if o.Protocol == "" {
		o.Protocol = "tcp"
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

// ScanHost scans a single host for open ports.
func ScanHost(ctx context.Context, hostname string, opts ScanOptions) (*ScanResult, error) {
	opts.defaults()

	laddr, err := GetLocalIP()
	if err != nil {
		return nil, fmt.Errorf("getting local IP: %w", err)
	}

	if opts.Stealth {
		if !canSocketBind(laddr) {
			return nil, fmt.Errorf("socket: operation not permitted (raw socket required for stealth scan)")
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

	if opts.Stealth {
		if !canSocketBind(laddr) {
			return nil, fmt.Errorf("socket: operation not permitted (raw socket required for stealth scan)")
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

	if opts.Stealth {
		if !canSocketBind(laddr) {
			return nil, fmt.Errorf("socket: operation not permitted (raw socket required for stealth scan)")
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
				if opts.Stealth {
					scanPortSyn(resultCh, opts.Protocol, hostname, job.service, job.port, laddr)
				} else {
					scanPortConnect(resultCh, opts.Protocol, hostname, job.service, job.port, opts.Timeout)
				}
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

// scanPortConnect performs a TCP connect scan on a single port.
func scanPortConnect(resultCh chan<- PortResult, protocol, hostname, service string, port int, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}
	address := hostname + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout(protocol, address, timeout)
	if err != nil {
		result.Open = false
		resultCh <- result
		return
	}
	conn.Close()
	result.Open = true
	resultCh <- result
}
