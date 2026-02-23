package gomap

import (
	"context"
	"fmt"
	"net"
	"time"
)

// TracerouteHop represents a single hop in a traceroute.
type TracerouteHop struct {
	// TTL is the time-to-live value for this hop.
	TTL int

	// IP is the IP address of the responding host.
	IP string

	// Hostname is the reverse DNS name (if resolved).
	Hostname string

	// RTT is the round-trip time for this hop.
	RTT time.Duration

	// TimedOut indicates the hop did not respond.
	TimedOut bool
}

// TracerouteResult contains the full traceroute output.
type TracerouteResult struct {
	Host string
	Hops []TracerouteHop
}

// TracerouteOptions configures traceroute behavior.
type TracerouteOptions struct {
	// MaxHops is the maximum TTL (default 30).
	MaxHops int

	// Timeout per hop (default 2s).
	Timeout time.Duration

	// Port to send TCP SYN to (default 80). Used for TCP traceroute.
	Port int

	// Retries per hop (default 2).
	Retries int
}

func (o *TracerouteOptions) defaults() {
	if o.MaxHops == 0 {
		o.MaxHops = 30
	}
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	if o.Port == 0 {
		o.Port = 80
	}
	if o.Retries == 0 {
		o.Retries = 2
	}
}

// Traceroute performs a UDP-based traceroute to the target host.
// It sends UDP packets with increasing TTL values and listens for
// ICMP Time Exceeded responses.
func Traceroute(ctx context.Context, host string, opts TracerouteOptions) (*TracerouteResult, error) {
	opts.defaults()

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses for host: %s", host)
	}

	// Prefer IPv4
	var targetIP net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			targetIP = ip
			break
		}
	}
	if targetIP == nil {
		targetIP = ips[0]
	}

	result := &TracerouteResult{Host: host}

	for ttl := 1; ttl <= opts.MaxHops; ttl++ {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}

		hop := traceHop(ctx, targetIP.String(), ttl, opts)
		result.Hops = append(result.Hops, hop)

		// Reached the destination
		if hop.IP == targetIP.String() {
			break
		}
	}

	return result, nil
}

// traceHop sends a probe at the given TTL and returns the hop result.
func traceHop(ctx context.Context, target string, ttl int, opts TracerouteOptions) TracerouteHop {
	hop := TracerouteHop{TTL: ttl, TimedOut: true}

	for attempt := 0; attempt <= opts.Retries; attempt++ {
		if ctx.Err() != nil {
			return hop
		}

		ip, rtt, err := traceHopImpl(ctx, target, ttl, opts)
		if err != nil {
			continue
		}

		hop.IP = ip
		hop.RTT = rtt
		hop.TimedOut = false

		// Reverse DNS lookup
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			hop.Hostname = names[0]
			// Trim trailing dot
			if len(hop.Hostname) > 0 && hop.Hostname[len(hop.Hostname)-1] == '.' {
				hop.Hostname = hop.Hostname[:len(hop.Hostname)-1]
			}
		}

		return hop
	}

	return hop
}

// String returns a human-readable traceroute output.
func (r *TracerouteResult) String() string {
	var s string
	s += fmt.Sprintf("traceroute to %s, %d hops max\n", r.Host, len(r.Hops))
	for _, h := range r.Hops {
		if h.TimedOut {
			s += fmt.Sprintf("  %2d  * * *\n", h.TTL)
		} else {
			name := h.IP
			if h.Hostname != "" {
				name = fmt.Sprintf("%s (%s)", h.Hostname, h.IP)
			}
			s += fmt.Sprintf("  %2d  %s  %s\n", h.TTL, name, h.RTT.Round(100*time.Microsecond))
		}
	}
	return s
}
