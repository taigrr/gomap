//go:build linux

package gomap

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"
	"time"
)

// SCTP chunk types
const (
	sctpINIT       = 1
	sctpINITACK    = 2
	sctpCOOKIEECHO = 10
	sctpABORT      = 6
)

// scanPortSCTPInit sends an SCTP INIT chunk and interprets the response.
func scanPortSCTPInit(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}

	resp, err := sendSCTPChunk(ctx, laddr, hostname, port, sctpINIT, timeout)
	if err != nil {
		result.setStateReason(PortFiltered, "no-response")
		resultCh <- result
		return
	}

	switch resp {
	case sctpINITACK:
		result.setStateReason(PortOpen, "init-ack")
	case sctpABORT:
		result.setStateReason(PortClosed, "abort")
	default:
		result.setStateReason(PortFiltered, "no-response")
	}

	resultCh <- result
}

// scanPortSCTPCookieEcho sends an SCTP COOKIE-ECHO chunk.
// Open ports silently drop it; closed ports respond with ABORT.
func scanPortSCTPCookieEcho(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}

	resp, err := sendSCTPChunk(ctx, laddr, hostname, port, sctpCOOKIEECHO, timeout)
	if err != nil {
		result.setStateReason(PortOpenFiltered, "no-response")
		resultCh <- result
		return
	}

	if resp == sctpABORT {
		result.setStateReason(PortClosed, "abort")
	} else {
		result.setStateReason(PortOpenFiltered, "no-response")
	}

	resultCh <- result
}

// sendSCTPChunk sends a raw SCTP chunk and returns the response chunk type.
func sendSCTPChunk(ctx context.Context, laddr, raddr string, port int, chunkType byte, timeout time.Duration) (byte, error) {
	targetIP := net.ParseIP(raddr)
	if targetIP == nil {
		ips, err := net.LookupIP(raddr)
		if err != nil || len(ips) == 0 {
			return 0, err
		}
		targetIP = ips[0]
	}

	// Create raw socket for SCTP (protocol 132)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, 132)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Build SCTP packet: common header (12 bytes) + chunk
	srcPort := uint16(randomPort(10000, 65535))
	dstPort := uint16(port)

	// Common header: src port (2), dst port (2), vtag (4), checksum (4)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], srcPort)
	binary.BigEndian.PutUint16(header[2:4], dstPort)
	// vtag = 0 for INIT, random for others
	if chunkType != sctpINIT {
		binary.BigEndian.PutUint32(header[4:8], 0x12345678)
	}

	// Chunk: type (1), flags (1), length (2), initiate tag (4), a-rwnd (4),
	// num outbound (2), num inbound (2), initial TSN (4)
	var chunk []byte
	if chunkType == sctpINIT {
		chunk = make([]byte, 20)
		chunk[0] = sctpINIT
		chunk[1] = 0
		binary.BigEndian.PutUint16(chunk[2:4], 20) // length
		binary.BigEndian.PutUint32(chunk[4:8], 0xAABBCCDD) // initiate tag
		binary.BigEndian.PutUint32(chunk[8:12], 65535) // a-rwnd
		binary.BigEndian.PutUint16(chunk[12:14], 1) // outbound streams
		binary.BigEndian.PutUint16(chunk[14:16], 1) // inbound streams
		binary.BigEndian.PutUint32(chunk[16:20], 1) // initial TSN
	} else {
		// COOKIE-ECHO: type (1), flags (1), length (2), cookie data
		chunk = make([]byte, 8)
		chunk[0] = sctpCOOKIEECHO
		chunk[1] = 0
		binary.BigEndian.PutUint16(chunk[2:4], 8)
		binary.BigEndian.PutUint32(chunk[4:8], 0xDEADBEEF)
	}

	packet := append(header, chunk...)
	// CRC32c checksum — simplified, zero for now (many stacks accept it)
	binary.BigEndian.PutUint32(packet[8:12], 0)

	var destAddr [4]byte
	copy(destAddr[:], targetIP.To4())
	sa := &syscall.SockaddrInet4{Port: 0, Addr: destAddr}

	if err := syscall.Sendto(fd, packet, 0, sa); err != nil {
		return 0, err
	}

	// Listen for response
	buf := make([]byte, 512)
	for {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return 0, err
		}
		if n < 20+12 {
			continue
		}
		// Skip IP header (IHL * 4)
		ihl := int(buf[0]&0x0f) * 4
		if n < ihl+12+1 {
			continue
		}
		// Check SCTP src/dst ports match
		respSrc := binary.BigEndian.Uint16(buf[ihl : ihl+2])
		respDst := binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])
		if respSrc != dstPort || respDst != srcPort {
			continue
		}
		// Return first chunk type
		if n >= ihl+12+1 {
			return buf[ihl+12], nil
		}
	}
}
