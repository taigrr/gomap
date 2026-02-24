package gomap

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// ScanEvent represents a single result event from a streaming scan.
// Consumers receive these as they are produced, without waiting for the
// entire scan to complete.
type ScanEvent struct {
	// Host identifies which host this result belongs to (for range/CIDR scans).
	Host string

	// Port is the scanned port result. Nil for host-level events.
	Port *PortResult

	// Done is true when all ports for this host have been scanned.
	Done bool

	// Error is non-nil if the scan encountered an error for this host.
	Error error
}

// ScanHostStream scans a single host and streams results over a channel.
// The channel is closed when the scan completes. The caller must drain
// the channel to avoid goroutine leaks.
//
// This is the preferred API for UIs and interactive applications that want
// to display results as they arrive.
func ScanHostStream(ctx context.Context, hostname string, opts ScanOptions) <-chan ScanEvent {
	out := make(chan ScanEvent, 64)
	go func() {
		defer close(out)
		opts.defaults()

		ips, err := net.LookupIP(hostname)
		if err != nil {
			out <- ScanEvent{Host: hostname, Error: fmt.Errorf("%w: %s: %v", ErrResolveHost, hostname, err)}
			return
		}
		if len(ips) == 0 {
			out <- ScanEvent{Host: hostname, Error: fmt.Errorf("%w: %s", ErrNoAddresses, hostname)}
			return
		}

		targetIP := selectIP(ips, opts.PreferIPv6)
		laddr, err := GetLocalAddr(targetIP.String())
		if err != nil {
			out <- ScanEvent{Host: hostname, Error: fmt.Errorf("getting local IP: %w", err)}
			return
		}

		if opts.ScanType.RequiresRawSocket() && !canSocketBind(laddr) {
			out <- ScanEvent{Host: hostname, Error: fmt.Errorf("%w: %s scan needs root or CAP_NET_RAW", ErrRawSocketRequired, opts.ScanType)}
			return
		}

		tr := newTracer(opts.TraceWriter)
		streamHostPorts(ctx, out, hostname, laddr, opts, tr)
	}()
	return out
}

// ScanCIDRStream scans a CIDR range and streams results over a channel.
// Results from different hosts are interleaved. Each host's completion
// is signaled by a ScanEvent with Done=true.
func ScanCIDRStream(ctx context.Context, cidr string, opts ScanOptions) <-chan ScanEvent {
	out := make(chan ScanEvent, 128)
	go func() {
		defer close(out)
		opts.defaults()

		laddr, err := GetLocalIP()
		if err != nil {
			out <- ScanEvent{Error: fmt.Errorf("getting local IP: %w", err)}
			return
		}

		hosts := CreateHostRange(cidr)
		if hosts == nil {
			out <- ScanEvent{Error: fmt.Errorf("%w: %s", ErrInvalidCIDR, cidr)}
			return
		}

		excludeSet := buildExcludeSet(opts.ExcludeHosts)
		tr := newTracer(opts.TraceWriter)

		// Determine host parallelism
		hostWorkers := 1
		if opts.MinHostgroup > 0 {
			hostWorkers = opts.MinHostgroup
		}
		if hostWorkers < 1 {
			hostWorkers = 1
		}
		if opts.MaxHostgroup > 0 && hostWorkers > opts.MaxHostgroup {
			hostWorkers = opts.MaxHostgroup
		}

		hostCh := make(chan string, len(hosts))
		go func() {
			for _, h := range hosts {
				if excludeSet[h] {
					continue
				}
				select {
				case hostCh <- h:
				case <-ctx.Done():
					close(hostCh)
					return
				}
			}
			close(hostCh)
		}()

		var wg sync.WaitGroup
		for i := 0; i < hostWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for h := range hostCh {
					if ctx.Err() != nil {
						return
					}
					hostCtx := ctx
					if opts.HostTimeout > 0 {
						var cancel context.CancelFunc
						hostCtx, cancel = context.WithTimeout(ctx, opts.HostTimeout)
						streamHostPorts(hostCtx, out, h, laddr, opts, tr)
						cancel()
					} else {
						streamHostPorts(hostCtx, out, h, laddr, opts, tr)
					}
				}
			}()
		}
		wg.Wait()
	}()
	return out
}

// streamHostPorts scans all ports on a host and sends results to the event channel.
func streamHostPorts(ctx context.Context, out chan<- ScanEvent, hostname, laddr string, opts ScanOptions, tr *tracer) {
	portList := resolvePortList(opts)

	tasks := len(portList)
	in := make(chan portJob, tasks)
	resultCh := make(chan PortResult, tasks)

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

	var rl *RateLimiter
	if opts.MinRate > 0 || opts.MaxRate > 0 {
		rl = NewRateLimiter(opts.MinRate, opts.MaxRate)
	}

	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range in {
				if ctx.Err() != nil {
					return
				}
				if rl != nil {
					rl.WaitCtx(ctx)
				}
				scanPort(ctx, resultCh, opts, hostname, laddr, job, tr)
				if opts.ScanDelay > 0 {
					select {
					case <-ctx.Done():
						return
					case <-sleepCtx(ctx, opts.ScanDelay):
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for result := range resultCh {
		if opts.OpenOnly && !result.Open {
			continue
		}
		out <- ScanEvent{
			Host: hostname,
			Port: &result,
		}
	}

	out <- ScanEvent{Host: hostname, Done: true}
}

// resolvePortList returns the port map for the given options.
func resolvePortList(opts ScanOptions) map[int]string {
	var portList map[int]string
	if len(opts.Ports) > 0 {
		portList = make(map[int]string, len(opts.Ports))
		for _, p := range opts.Ports {
			portList[p] = LookupService(p)
		}
	} else if opts.FastScan {
		portList = CommonPorts
	} else {
		portList = DetailedPorts
	}

	if len(opts.ExcludePorts) > 0 {
		excludeSet := make(map[int]bool, len(opts.ExcludePorts))
		for _, p := range opts.ExcludePorts {
			excludeSet[p] = true
		}
		filtered := make(map[int]string, len(portList))
		for p, svc := range portList {
			if !excludeSet[p] {
				filtered[p] = svc
			}
		}
		portList = filtered
	}

	return portList
}

// sleepCtx blocks for at most duration d, returning early if ctx is canceled.
func sleepCtx(ctx context.Context, d time.Duration) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
		}
	}()
	return ch
}
