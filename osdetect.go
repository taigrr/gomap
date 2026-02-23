package gomap

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// OSFingerprint contains TCP/IP stack characteristics used for OS identification.
type OSFingerprint struct {
	// SEQ: TCP ISN (Initial Sequence Number) analysis
	SEQ SEQFingerprint

	// OPS: TCP options in SYN-ACK responses
	OPS OPSFingerprint

	// WIN: TCP initial window sizes
	WIN WINFingerprint

	// T1-T7: Response characteristics to different probes
	Probes [7]ProbeFingerprint

	// U1: UDP probe response characteristics
	U1 UDPFingerprint

	// IE: ICMP echo response characteristics
	IE ICMPFingerprint
}

// SEQFingerprint contains TCP sequence analysis data.
type SEQFingerprint struct {
	// SP: TCP ISN sequence predictability (0=constant, >5=random)
	SP int
	// GCD: Greatest common divisor of ISN differences
	GCD int
	// ISR: ISN counter rate (ISNs per second)
	ISR int
	// TI: IPID sequence type (I=incremental, RI=random increment, etc.)
	TI string
	// CI: Closed-port IPID sequence
	CI string
	// II: ICMP IPID sequence
	II string
	// SS: Shared IP ID sequence (S=yes, O=no)
	SS string
	// TS: TCP timestamp option (U=unsupported, 0-F=Hz)
	TS string
}

// OPSFingerprint contains TCP options from SYN-ACK responses.
type OPSFingerprint struct {
	// O1-O6: TCP options string from each of 6 SYN probes
	Options [6]string
}

// WINFingerprint contains TCP initial window sizes.
type WINFingerprint struct {
	// W1-W6: Window sizes from each of 6 SYN probes
	Windows [6]int
}

// ProbeFingerprint contains the response to a specific TCP probe.
type ProbeFingerprint struct {
	// R: Did we get a response? (Y/N)
	Responded bool
	// DF: Don't fragment bit set (Y/N)
	DF bool
	// T: IP TTL (time to live)
	TTL int
	// W: TCP window size
	Window int
	// S: TCP sequence number behavior
	SeqBehavior string
	// A: TCP acknowledgment behavior
	AckBehavior string
	// F: TCP flags
	Flags string
	// O: TCP options
	Options string
	// RD: RST data CRC
	RD int
	// Q: Quirks
	Quirks string
}

// UDPFingerprint contains characteristics from the UDP probe response.
type UDPFingerprint struct {
	Responded   bool
	DF          bool
	TTL         int
	IPLen       int
	UnusedField int
	RIPL        string
	RID         string
	RIPCK       string
	RUCK        string
	RUD         string
}

// ICMPFingerprint contains characteristics from ICMP echo responses.
type ICMPFingerprint struct {
	Responded bool
	DFI       string
	TTL       int
	CD        string
}

// OSMatch represents a potential OS match with confidence score.
type OSMatch struct {
	Name       string
	Family     string
	Generation string
	DeviceType string
	CPE        []string
	Accuracy   float64
}

// OSDetectResult contains the results of OS detection for a host.
type OSDetectResult struct {
	Host        string
	Fingerprint OSFingerprint
	Matches     []OSMatch
	// Raw is the nmap-compatible fingerprint string
	Raw string
}

// DetectOS attempts to identify the operating system of a target host by
// analyzing its TCP/IP stack behavior.
//
// This requires:
// - At least one open port and one closed port on the target
// - Raw socket privileges (Linux: root or CAP_NET_RAW)
//
// The function sends a series of carefully crafted probes and analyzes the
// responses to build a fingerprint, which is then compared against a
// database of known OS signatures.
func DetectOS(ctx context.Context, host string, openPort, closedPort int, opts ScanOptions) (*OSDetectResult, error) {
	opts.defaults()

	laddr, err := GetLocalIP()
	if err != nil {
		return nil, fmt.Errorf("getting local IP: %w", err)
	}

	if !canSocketBind(laddr) {
		return nil, fmt.Errorf("OS detection requires raw socket privileges")
	}

	result := &OSDetectResult{
		Host: host,
	}

	// Resolve host
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("resolving host: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses for host: %s", host)
	}

	targetIP := ips[len(ips)-1].String()

	// Phase 1: Send 6 SYN probes to the open port to gather SEQ/OPS/WIN data
	fp, err := sendOSProbes(ctx, laddr, targetIP, openPort, closedPort, opts.Timeout)
	if err != nil {
		return nil, fmt.Errorf("OS probe failed: %w", err)
	}

	result.Fingerprint = *fp
	result.Raw = formatFingerprint(fp)

	return result, nil
}

// formatFingerprint creates an nmap-compatible fingerprint string.
func formatFingerprint(fp *OSFingerprint) string {
	var b strings.Builder

	// SEQ line
	fmt.Fprintf(&b, "SEQ(SP=%X%%GCD=%X%%ISR=%X%%TI=%s%%CI=%s%%II=%s%%SS=%s%%TS=%s)\n",
		fp.SEQ.SP, fp.SEQ.GCD, fp.SEQ.ISR, fp.SEQ.TI, fp.SEQ.CI, fp.SEQ.II, fp.SEQ.SS, fp.SEQ.TS)

	// OPS line
	b.WriteString("OPS(")
	for i, opt := range fp.OPS.Options {
		if i > 0 {
			b.WriteByte('%')
		}
		fmt.Fprintf(&b, "O%d=%s", i+1, opt)
	}
	b.WriteString(")\n")

	// WIN line
	b.WriteString("WIN(")
	for i, w := range fp.WIN.Windows {
		if i > 0 {
			b.WriteByte('%')
		}
		fmt.Fprintf(&b, "W%d=%X", i+1, w)
	}
	b.WriteString(")\n")

	// T1-T7 lines
	for i, p := range fp.Probes {
		r := "N"
		if p.Responded {
			r = "Y"
		}
		df := "N"
		if p.DF {
			df = "Y"
		}
		fmt.Fprintf(&b, "T%d(R=%s%%DF=%s%%T=%X%%W=%X%%S=%s%%A=%s%%F=%s%%O=%s%%RD=%X%%Q=%s)\n",
			i+1, r, df, p.TTL, p.Window, p.SeqBehavior, p.AckBehavior, p.Flags, p.Options, p.RD, p.Quirks)
	}

	return b.String()
}

// sendOSProbes sends the OS detection probe sequence.
// This is implemented in platform-specific files.
func sendOSProbes(ctx context.Context, laddr, raddr string, openPort, closedPort int, timeout time.Duration) (*OSFingerprint, error) {
	return sendOSProbesImpl(ctx, laddr, raddr, openPort, closedPort, timeout)
}
