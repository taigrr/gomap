//go:build linux

package gomap

import (
	"context"
	"fmt"
	"net"
	"time"
)

// IPProtocolScan sends raw IP packets for each protocol number (0-255)
// and determines which IP protocols are supported by the target.
// Matches nmap's -sO scan type.
func IPProtocolScan(ctx context.Context, host string, opts ScanOptions) ([]ProtocolResult, error) {
	opts.defaults()

	laddr, err := GetLocalAddr(host)
	if err != nil {
		return nil, fmt.Errorf("getting local address: %w", err)
	}
	if !canSocketBind(laddr) {
		return nil, fmt.Errorf("IP protocol scan requires raw socket privileges")
	}

	protocols := defaultProtocols()
	if len(opts.Ports) > 0 {
		protocols = opts.Ports
	}

	type job struct {
		proto int
	}

	in := make(chan job, len(protocols))
	resultCh := make(chan ProtocolResult, len(protocols))

	go func() {
		for _, p := range protocols {
			select {
			case in <- job{proto: p}:
			case <-ctx.Done():
				close(in)
				return
			}
		}
		close(in)
	}()

	workers := opts.Workers
	if workers > len(protocols) {
		workers = len(protocols)
	}

	var wg syncWaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range in {
				if ctx.Err() != nil {
					return
				}
				result := probeProtocol(ctx, laddr, host, j.proto, opts.Timeout)
				if opts.TraceWriter != nil {
					tr := newTracer(opts.TraceWriter)
					tr.tracePacket(PacketSent, fmt.Sprintf("IP-PROTO-%d", j.proto), laddr, 0, host, 0, "")
				}
				resultCh <- result
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var results []ProtocolResult
	for r := range resultCh {
		results = append(results, r)
	}
	return results, nil
}

func probeProtocol(ctx context.Context, laddr, host string, proto int, timeout time.Duration) ProtocolResult {
	result := ProtocolResult{
		Protocol: proto,
		Name:     lookupProtocolName(proto),
	}

	// Send a minimal IP packet with the given protocol number
	network := fmt.Sprintf("ip4:%d", proto)
	conn, err := net.DialTimeout(network, host, timeout)
	if err != nil {
		result.State = PortFiltered
		result.Reason = "no-response"
		return result
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// Send a single byte
	_, err = conn.Write([]byte{0})
	if err != nil {
		result.State = PortFiltered
		result.Reason = "no-response"
		return result
	}

	// Try to read — any response means protocol is supported
	buf := make([]byte, readBufferSize)
	_, err = conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.State = PortOpenFiltered
			result.Open = true
			result.Reason = "no-response"
			return result
		}
		// ICMP protocol unreachable = closed
		result.State = PortClosed
		result.Reason = "proto-unreach"
		return result
	}

	result.State = PortOpen
	result.Open = true
	result.Reason = "proto-response"
	return result
}
