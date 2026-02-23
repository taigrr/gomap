//go:build linux

package gomap

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

type tcpHeader struct {
	SrcPort       uint16
	DstPort       uint16
	SeqNum        uint32
	AckNum        uint32
	Flags         uint16
	Window        uint16
	ChkSum        uint16
	UrgentPointer uint16
}

type tcpOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

// scanPortSyn performs a SYN scan on a single port (Linux only).
func scanPortSyn(resultCh chan<- PortResult, protocol, hostname, service string, port int, laddr string) {
	result := PortResult{Port: port, Service: service}
	ack := make(chan bool, 1)

	go recvSynAck(laddr, hostname, uint16(port), ack)
	sendSyn(laddr, hostname, uint16(randomPort(10000, 65535)), uint16(port))

	select {
	case r := <-ack:
		result.Open = r
		resultCh <- result
	case <-time.After(3 * time.Second):
		result.Open = false
		resultCh <- result
	}
}

func sendSyn(laddr string, raddr string, sport uint16, dport uint16) error {
	op := []tcpOption{
		{
			Kind:   2,
			Length: 4,
			Data:   []byte{0x05, 0xb4},
		},
		{
			Kind: 0,
		},
	}

	tcpH := tcpHeader{
		SrcPort:       sport,
		DstPort:       dport,
		SeqNum:        rand.Uint32(),
		AckNum:        0,
		Flags:         0x8002,
		Window:        8192,
		ChkSum:        0,
		UrgentPointer: 0,
	}

	conn, err := net.Dial("ip4:tcp", raddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	buff := new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, tcpH)

	for i := range op {
		binary.Write(buff, binary.BigEndian, op[i].Kind)
		binary.Write(buff, binary.BigEndian, op[i].Length)
		binary.Write(buff, binary.BigEndian, op[i].Data)
	}

	binary.Write(buff, binary.BigEndian, [6]byte{})
	data := buff.Bytes()
	checkSum := tcpChecksum(data, ipToBytes(laddr), ipToBytes(raddr))
	tcpH.ChkSum = checkSum

	buff = new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, tcpH)

	for i := range op {
		binary.Write(buff, binary.BigEndian, op[i].Kind)
		binary.Write(buff, binary.BigEndian, op[i].Length)
		binary.Write(buff, binary.BigEndian, op[i].Data)
	}
	binary.Write(buff, binary.BigEndian, [6]byte{})

	conn.Write(buff.Bytes())
	return nil
}

func recvSynAck(laddr string, raddr string, port uint16, res chan<- bool) error {
	listenAddr, err := net.ResolveIPAddr("ip4", laddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenIP("ip4:tcp", listenAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	for {
		buff := make([]byte, 1024)
		_, addr, err := conn.ReadFrom(buff)
		if err != nil {
			continue
		}
		if addr.String() != raddr || buff[13] != 0x12 {
			continue
		}

		var packetport uint16
		binary.Read(bytes.NewReader(buff), binary.BigEndian, &packetport)
		if port != packetport {
			continue
		}

		res <- true
		return nil
	}
}

func tcpChecksum(data []byte, src, dst [4]byte) uint16 {
	pseudoHeader := []byte{
		src[0], src[1], src[2], src[3],
		dst[0], dst[1], dst[2], dst[3],
		0,
		6,
		0,
		byte(len(data)),
	}

	totalLength := len(pseudoHeader) + len(data)
	if totalLength%2 != 0 {
		totalLength++
	}

	d := make([]byte, 0, totalLength)
	d = append(d, pseudoHeader...)
	d = append(d, data...)

	var sum uint32
	for i := 0; i < len(d)-1; i += 2 {
		sum += uint32(uint16(d[i])<<8 | uint16(d[i+1]))
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return ^uint16(sum)
}

func ipToBytes(addr string) [4]byte {
	s := strings.Split(addr, ".")
	b0, _ := strconv.Atoi(s[0])
	b1, _ := strconv.Atoi(s[1])
	b2, _ := strconv.Atoi(s[2])
	b3, _ := strconv.Atoi(s[3])
	return [4]byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}

func randomPort(min, max int) int {
	return rand.Intn(max-min) + min
}
