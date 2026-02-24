//go:build linux

package gomap

import (
	"encoding/binary"
	"net"
	"syscall"
)

// sendFragmentedPacket sends a TCP packet split into IP fragments.
// mtu controls the fragment size (default 8 = minimum, 0 = default MTU of 8).
// This is used for firewall/IDS evasion (-f flag).
func sendFragmentedPacket(laddr, raddr string, sport, dport, flags uint16, mtu int) error {
	if mtu <= 0 {
		mtu = 8 // minimum fragment offset unit
	}
	// Fragment offset must be multiple of 8
	mtu = (mtu / 8) * 8
	if mtu < 8 {
		mtu = 8
	}

	srcIP := net.ParseIP(laddr).To4()
	dstIP := net.ParseIP(raddr).To4()
	if srcIP == nil || dstIP == nil {
		return &net.OpError{Op: "fragment", Err: net.InvalidAddrError(raddr)}
	}

	// Build TCP header (20 bytes minimum)
	tcpLen := 20
	tcp := make([]byte, tcpLen)
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], 0x12345678) // seq
	binary.BigEndian.PutUint32(tcp[8:12], 0)         // ack
	tcp[12] = 0x50                                    // data offset = 5 words
	tcp[13] = byte(flags)                             // flags
	binary.BigEndian.PutUint16(tcp[14:16], 8192)     // window

	// Checksum
	pseudo := make([]byte, 12+tcpLen)
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))
	copy(pseudo[12:], tcp)
	csum := ipChecksum(pseudo)
	binary.BigEndian.PutUint16(tcp[16:18], csum)

	// Create raw IP socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	// Fragment the TCP payload
	id := uint16(randomPort(1, 65535))
	offset := 0
	remaining := tcp

	for len(remaining) > 0 {
		fragSize := mtu
		if fragSize > len(remaining) {
			fragSize = len(remaining)
		}
		// Pad to 8-byte boundary for non-last fragments
		isLast := fragSize >= len(remaining)
		if !isLast && fragSize%8 != 0 {
			fragSize = (fragSize / 8) * 8
		}

		frag := remaining[:fragSize]
		remaining = remaining[fragSize:]

		// Build IP header (20 bytes)
		ipHeader := make([]byte, 20+len(frag))
		ipHeader[0] = 0x45 // version 4, IHL 5
		binary.BigEndian.PutUint16(ipHeader[2:4], uint16(20+len(frag)))
		binary.BigEndian.PutUint16(ipHeader[4:6], id)

		// Fragment offset (in 8-byte units) + flags
		fragOff := uint16(offset / 8)
		if !isLast {
			fragOff |= 0x2000 // More Fragments flag
		}
		binary.BigEndian.PutUint16(ipHeader[6:8], fragOff)

		ipHeader[8] = 64 // TTL
		ipHeader[9] = 6  // TCP
		copy(ipHeader[12:16], srcIP)
		copy(ipHeader[16:20], dstIP)

		// IP header checksum
		csum := ipChecksum(ipHeader[:20])
		binary.BigEndian.PutUint16(ipHeader[10:12], csum)

		copy(ipHeader[20:], frag)

		var destAddr [4]byte
		copy(destAddr[:], dstIP)
		sa := &syscall.SockaddrInet4{Addr: destAddr}

		if err := syscall.Sendto(fd, ipHeader, 0, sa); err != nil {
			return err
		}

		offset += fragSize
	}

	return nil
}

func ipChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
}
