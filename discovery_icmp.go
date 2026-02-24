package gomap

import (
	"context"
	"net"
	"time"
)

// probeICMPTimestamp sends an ICMP timestamp request (type 13).
func probeICMPTimestamp(ctx context.Context, host string, timeout time.Duration) bool {
	return probeICMPType(ctx, host, 13, timeout)
}

// probeICMPNetmask sends an ICMP address mask request (type 17).
func probeICMPNetmask(ctx context.Context, host string, timeout time.Duration) bool {
	return probeICMPType(ctx, host, 17, timeout)
}

func probeICMPType(ctx context.Context, host string, icmpType byte, timeout time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}

	proto := "ip4:icmp"
	if IsIPv6(host) {
		return false // timestamp/netmask are IPv4 only
	}

	conn, err := net.DialTimeout(proto, host, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// Build ICMP message: type, code=0, checksum, id, seq, [payload]
	var msg []byte
	switch icmpType {
	case 13: // Timestamp: 20 bytes total
		msg = make([]byte, 20)
		msg[0] = 13 // Timestamp request
		// id=1, seq=1
		msg[4] = 0
		msg[5] = 1
		msg[6] = 0
		msg[7] = 1
		// Originate timestamp (ms since midnight UTC)
		now := time.Now().UTC()
		ms := uint32(now.Hour()*3600000 + now.Minute()*60000 + now.Second()*1000 + now.Nanosecond()/1000000)
		msg[8] = byte(ms >> 24)
		msg[9] = byte(ms >> 16)
		msg[10] = byte(ms >> 8)
		msg[11] = byte(ms)
	case 17: // Address mask: 12 bytes
		msg = make([]byte, 12)
		msg[0] = 17 // Address mask request
		msg[4] = 0
		msg[5] = 1
		msg[6] = 0
		msg[7] = 1
	default:
		return false
	}

	// Compute checksum
	var sum uint32
	for i := 0; i < len(msg)-1; i += 2 {
		sum += uint32(msg[i])<<8 | uint32(msg[i+1])
	}
	if len(msg)%2 == 1 {
		sum += uint32(msg[len(msg)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	cs := ^uint16(sum)
	msg[2] = byte(cs >> 8)
	msg[3] = byte(cs)

	if _, err := conn.Write(msg); err != nil {
		return false
	}

	buf := make([]byte, readBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}

	// Any response means host is alive
	return n > 0
}
