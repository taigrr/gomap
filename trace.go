package gomap

import (
	"fmt"
	"os"
	"time"
)

// PacketDirection indicates whether a packet was sent or received.
type PacketDirection string

const (
	PacketSent     PacketDirection = "SENT"
	PacketReceived PacketDirection = "RCVD"
)

// TracePacket logs a packet event when packet tracing is enabled.
func TracePacket(dir PacketDirection, proto, src, dst string, srcPort, dstPort int, flags string) {
	ts := time.Now().Format("15:04:05.000")
	fmt.Fprintf(os.Stderr, "TRACE %s [%s] %s %s:%d > %s:%d %s\n",
		ts, dir, proto, src, srcPort, dst, dstPort, flags)
}
