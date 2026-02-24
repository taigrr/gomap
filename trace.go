package gomap

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// PacketDirection indicates whether a packet was sent or received.
type PacketDirection string

const (
	PacketSent     PacketDirection = "SENT"
	PacketReceived PacketDirection = "RCVD"
)

var (
	traceStart     time.Time
	traceStartOnce sync.Once
)

// initTraceTimer initializes the packet trace start time.
// Call this once at scan start.
func initTraceTimer() {
	traceStartOnce.Do(func() {
		traceStart = time.Now()
	})
}

// tracePacket logs a packet event when packet tracing is enabled.
// Format matches nmap: SENT (0.0412s) TCP 192.168.1.1:54321 > 10.0.0.1:80 S ttl=64
func tracePacket(dir PacketDirection, proto, src string, srcPort int, dst string, dstPort int, detail string) {
	initTraceTimer()
	elapsed := time.Since(traceStart).Seconds()
	if srcPort > 0 && dstPort > 0 {
		fmt.Fprintf(os.Stderr, "%s (%.4fs) %s %s:%d > %s:%d %s\n",
			dir, elapsed, proto, src, srcPort, dst, dstPort, detail)
	} else if dstPort > 0 {
		fmt.Fprintf(os.Stderr, "%s (%.4fs) %s %s > %s:%d %s\n",
			dir, elapsed, proto, src, dst, dstPort, detail)
	} else {
		fmt.Fprintf(os.Stderr, "%s (%.4fs) %s %s > %s %s\n",
			dir, elapsed, proto, src, dst, detail)
	}
}

// tcpFlagString returns a human-readable flag string for a scan type,
// matching nmap's packet trace format (e.g., "S" for SYN, "F" for FIN).
func tcpFlagString(st ScanType) string {
	switch st {
	case SYNScan:
		return "S"
	case FINScan:
		return "F"
	case XmasScan:
		return "FPU"
	case NullScan:
		return ""
	case ACKScan:
		return "A"
	case WindowScan:
		return "A"
	case MaimonScan:
		return "FA"
	case SCTPInitScan:
		return "INIT"
	case SCTPCookieEchoScan:
		return "COOKIE-ECHO"
	default:
		return ""
	}
}

// traceConnect logs a connect() attempt when packet tracing is enabled.
func traceConnect(dir PacketDirection, proto, dst string, dstPort int, result string) {
	initTraceTimer()
	elapsed := time.Since(traceStart).Seconds()
	fmt.Fprintf(os.Stderr, "%s (%.4fs) %s > %s:%d %s\n",
		dir, elapsed, proto, dst, dstPort, result)
}
