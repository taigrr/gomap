//go:build linux

package gomap

import (
	"context"
	"time"
)

// scanPortSyn performs a SYN (half-open) scan on a single port.
func scanPortSyn(ctx context.Context, resultCh chan<- PortResult, protocol, hostname, service string, port int, laddr string, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}
	responseCh := make(chan rawResponse, 1)

	sport := uint16(randomPort(10000, 65535))
	go listenForResponse(laddr, hostname, uint16(port), sport, responseCh, timeout)

	time.Sleep(5 * time.Millisecond)

	if ctx.Err() != nil {
		result.State = PortFiltered
		resultCh <- result
		return
	}

	err := sendTCPPacket(laddr, hostname, sport, uint16(port), tcpSYN)
	if err != nil {
		result.State = PortFiltered
		resultCh <- result
		return
	}

	select {
	case <-ctx.Done():
		result.State = PortFiltered
	case resp := <-responseCh:
		if resp.flags&tcpSYN != 0 && resp.flags&tcpACK != 0 {
			result.Open = true
			result.State = PortOpen
		} else if resp.flags&tcpRST != 0 {
			result.State = PortClosed
		} else {
			result.State = PortFiltered
		}
	case <-time.After(timeout):
		result.State = PortFiltered
	}

	resultCh <- result
}
