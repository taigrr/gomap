//go:build linux

package gomap

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// IdleScanConfig holds the zombie host configuration for idle scanning.
type IdleScanConfig struct {
	// ZombieHost is the IP or hostname of the zombie (idle) host.
	ZombieHost string
	// ZombiePort is the port on the zombie to probe (default 80).
	ZombiePort int
}

// scanPortIdle implements the idle/zombie scan technique.
// It probes the zombie's IP ID, triggers the target to send a RST to the zombie,
// then checks if the zombie's IP ID incremented.
func scanPortIdle(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration, zombie IdleScanConfig) {
	result := PortResult{Port: port, Service: service}

	if zombie.ZombieHost == "" {
		result.setStateReason(PortFiltered, "no-zombie")
		resultCh <- result
		return
	}
	if zombie.ZombiePort == 0 {
		zombie.ZombiePort = 80
	}

	// Step 1: Get zombie's current IP ID by sending SYN/ACK → expect RST with IP ID
	id1, err := probeZombieIPID(laddr, zombie.ZombieHost, zombie.ZombiePort, timeout)
	if err != nil {
		result.setStateReason(PortFiltered, "zombie-error")
		resultCh <- result
		return
	}

	// Step 2: Send a forged SYN to the target (spoofed from zombie's IP)
	sport := uint16(randomPort(10000, 65535))
	err = sendTCPPacket(zombie.ZombieHost, hostname, sport, uint16(port), tcpSYN)
	if err != nil {
		result.setStateReason(PortFiltered, "send-error")
		resultCh <- result
		return
	}

	// Wait for the target to respond to the zombie
	time.Sleep(200 * time.Millisecond)

	// Step 3: Probe zombie's IP ID again
	id2, err := probeZombieIPID(laddr, zombie.ZombieHost, zombie.ZombiePort, timeout)
	if err != nil {
		result.setStateReason(PortFiltered, "zombie-error")
		resultCh <- result
		return
	}

	// Analyze: if ID incremented by 2, port is open (zombie got SYN/ACK from target,
	// sent RST back, incrementing ID). If incremented by 1, port is closed/filtered.
	diff := id2 - id1
	if diff == 2 {
		result.setStateReason(PortOpen, "ipid-increment")
	} else if diff == 1 {
		result.setStateReason(PortClosed, "ipid-no-increment")
	} else {
		// ID jumped by more — zombie is not idle enough
		result.setStateReason(PortFiltered, "zombie-not-idle")
	}

	resultCh <- result
}

// probeZombieIPID sends a SYN/ACK to the zombie to elicit a RST and reads the IP ID.
func probeZombieIPID(laddr, zombie string, port int, timeout time.Duration) (uint16, error) {
	responseCh := make(chan rawResponse, 1)
	sport := uint16(randomPort(10000, 65535))

	// Listen for RST
	go listenForIPID(laddr, zombie, uint16(port), sport, responseCh, timeout)
	time.Sleep(5 * time.Millisecond)

	// Send SYN/ACK to zombie → should elicit RST
	err := sendTCPPacket(laddr, zombie, sport, uint16(port), tcpSYN|tcpACK)
	if err != nil {
		return 0, err
	}

	select {
	case resp := <-responseCh:
		return resp.window, nil // we reuse window field for IP ID
	case <-time.After(timeout):
		return 0, fmt.Errorf("timeout waiting for zombie RST")
	}
}

// listenForIPID listens for a response and extracts the IP ID field.
func listenForIPID(laddr, raddr string, dport, sport uint16, ch chan<- rawResponse, timeout time.Duration) {
	network := "ip4"
	if IsIPv6(laddr) {
		network = "ip6"
	}
	listenAddr, err := net.ResolveIPAddr(network, laddr)
	if err != nil {
		return
	}

	conn, err := net.ListenIP(ipProtocol(laddr, "tcp"), listenAddr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout + 100*time.Millisecond))

	// We need to read the IP header to get the IP ID
	// On Linux, raw IP sockets include the IP header
	buf := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if addr.String() != raddr || n < 40 {
			continue
		}

		// IP header: byte 4-5 = IP ID
		ipID := binary.BigEndian.Uint16(buf[4:6])

		// TCP header starts after IP header
		ihl := int(buf[0]&0x0f) * 4
		if n < ihl+4 {
			continue
		}

		srcPort := binary.BigEndian.Uint16(buf[ihl : ihl+2])
		dstPort := binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])

		if srcPort != dport || dstPort != sport {
			continue
		}

		// Return IP ID in the window field
		ch <- rawResponse{flags: 0, window: ipID}
		return
	}
}
