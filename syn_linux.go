//go:build linux

package gomap

import (
	"time"
)

// scanPortSyn performs a SYN (half-open) scan on a single port.
// Sends SYN, waits for SYN-ACK (open) or RST (closed).
func scanPortSyn(resultCh chan<- PortResult, protocol, hostname, service string, port int, laddr string) {
	result := PortResult{Port: port, Service: service}
	responseCh := make(chan rawResponse, 1)

	sport := uint16(randomPort(10000, 65535))
	go listenForResponse(laddr, hostname, uint16(port), sport, responseCh, 3*time.Second)

	time.Sleep(5 * time.Millisecond)

	err := sendTCPPacket(laddr, hostname, sport, uint16(port), tcpSYN)
	if err != nil {
		result.State = PortFiltered
		resultCh <- result
		return
	}

	select {
	case resp := <-responseCh:
		if resp.flags&tcpSYN != 0 && resp.flags&tcpACK != 0 {
			// SYN-ACK = open
			result.Open = true
			result.State = PortOpen
		} else if resp.flags&tcpRST != 0 {
			// RST = closed
			result.State = PortClosed
		} else {
			result.State = PortFiltered
		}
	case <-time.After(3 * time.Second):
		result.State = PortFiltered
	}

	resultCh <- result
}
