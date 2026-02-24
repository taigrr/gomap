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
// OSScanGuessThreshold is the default confidence threshold for OS match
// reporting. With --osscan-guess, this is lowered to report more aggressive
// guesses. Matches nmap's OSSCAN_GUESS_THRESHOLD (0.85).
const OSScanGuessThreshold = 0.85

// OSScanGuessAggressiveThreshold is used when --osscan-guess is enabled.
// Any match above this threshold is reported.
const OSScanGuessAggressiveThreshold = 0.50

// DetectOS performs OS fingerprinting against a host by sending TCP/IP probes
// to an open and a closed port, then matching the responses against the nmap
// OS fingerprint database. Both openPort and closedPort must be known in advance.
func DetectOS(ctx context.Context, host string, openPort, closedPort int, opts ScanOptions) (*OSDetectResult, error) {
	opts.defaults()

	// --osscan-limit: skip if we don't have both an open and closed port
	if opts.OSScanLimit && (openPort <= 0 || closedPort <= 0) {
		return &OSDetectResult{
			Host: host,
		}, nil
	}

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

	// Determine number of OS detection attempts
	maxTries := 1
	if opts.MaxOSTries > 0 {
		maxTries = opts.MaxOSTries
	}

	var bestFP *OSFingerprint
	var bestMatches []OSMatch

	for attempt := 0; attempt < maxTries; attempt++ {
		if ctx.Err() != nil {
			break
		}

		fp, err := sendOSProbes(ctx, laddr, targetIP, openPort, closedPort, opts.Timeout)
		if err != nil {
			if attempt == maxTries-1 {
				return nil, fmt.Errorf("OS probe failed: %w", err)
			}
			continue
		}

		bestFP = fp

		osdb, err := DefaultOSDB()
		if err == nil && osdb != nil {
			fpMap := fingerprintToMap(fp)
			dbMatches := osdb.MatchOS(fpMap)

			threshold := OSScanGuessThreshold
			if opts.OSScanGuess {
				threshold = OSScanGuessAggressiveThreshold
			}

			var matches []OSMatch
			for _, dm := range dbMatches {
				if dm.Accuracy < threshold {
					continue
				}
				match := OSMatch{
					Name:     dm.Name,
					CPE:      dm.CPE,
					Accuracy: dm.Accuracy,
				}
				if len(dm.Classes) > 0 {
					match.Family = dm.Classes[0].Family
					match.Generation = dm.Classes[0].Generation
					match.DeviceType = dm.Classes[0].DeviceType
				}
				matches = append(matches, match)
			}

			// Keep best result across attempts
			if len(matches) > len(bestMatches) {
				bestMatches = matches
			}

			// Perfect match — stop retrying
			if len(matches) > 0 && matches[0].Accuracy >= 1.0 {
				break
			}
		}
	}

	if bestFP != nil {
		result.Fingerprint = *bestFP
		result.Raw = formatFingerprint(bestFP)
	}
	result.Matches = bestMatches

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
		responded := "N"
		if p.Responded {
			responded = "Y"
		}
		df := "N"
		if p.DF {
			df = "Y"
		}
		fmt.Fprintf(&b, "T%d(R=%s%%DF=%s%%T=%X%%W=%X%%S=%s%%A=%s%%F=%s%%O=%s%%RD=%X%%Q=%s)\n",
			i+1, responded, df, p.TTL, p.Window, p.SeqBehavior, p.AckBehavior, p.Flags, p.Options, p.RD, p.Quirks)
	}

	return b.String()
}

// fingerprintToMap converts an OSFingerprint struct to the map format
// expected by probedb.OSDB.MatchOS. Keys use the nmap-os-db format:
// SEQ, OPS, WIN, T1-T7, U1, IE.
func fingerprintToMap(fp *OSFingerprint) map[string]map[string]string {
	sections := make(map[string]map[string]string)

	// SEQ
	sections["SEQ"] = map[string]string{
		"SP":  fmt.Sprintf("%X", fp.SEQ.SP),
		"GCD": fmt.Sprintf("%X", fp.SEQ.GCD),
		"ISR": fmt.Sprintf("%X", fp.SEQ.ISR),
		"TI":  fp.SEQ.TI,
		"CI":  fp.SEQ.CI,
		"II":  fp.SEQ.II,
		"SS":  fp.SEQ.SS,
		"TS":  fp.SEQ.TS,
	}

	// OPS
	ops := make(map[string]string)
	for i, opt := range fp.OPS.Options {
		ops[fmt.Sprintf("O%d", i+1)] = opt
	}
	sections["OPS"] = ops

	// WIN
	win := make(map[string]string)
	for i, w := range fp.WIN.Windows {
		win[fmt.Sprintf("W%d", i+1)] = fmt.Sprintf("%X", w)
	}
	sections["WIN"] = win

	// T1-T7
	for i, p := range fp.Probes {
		responded := "N"
		if p.Responded {
			responded = "Y"
		}
		df := "N"
		if p.DF {
			df = "Y"
		}
		sections[fmt.Sprintf("T%d", i+1)] = map[string]string{
			"R":  responded,
			"DF": df,
			"T":  fmt.Sprintf("%X", p.TTL),
			"W":  fmt.Sprintf("%X", p.Window),
			"S":  p.SeqBehavior,
			"A":  p.AckBehavior,
			"F":  p.Flags,
			"O":  p.Options,
			"RD": fmt.Sprintf("%X", p.RD),
			"Q":  p.Quirks,
		}
	}

	// U1
	if fp.U1.Responded {
		u1 := map[string]string{"R": "Y"}
		df := "N"
		if fp.U1.DF {
			df = "Y"
		}
		u1["DF"] = df
		u1["T"] = fmt.Sprintf("%X", fp.U1.TTL)
		u1["IPL"] = fmt.Sprintf("%X", fp.U1.IPLen)
		u1["UN"] = fmt.Sprintf("%X", fp.U1.UnusedField)
		u1["RIPL"] = fp.U1.RIPL
		u1["RID"] = fp.U1.RID
		u1["RIPCK"] = fp.U1.RIPCK
		u1["RUCK"] = fp.U1.RUCK
		u1["RUD"] = fp.U1.RUD
		sections["U1"] = u1
	} else {
		sections["U1"] = map[string]string{"R": "N"}
	}

	// IE
	if fp.IE.Responded {
		sections["IE"] = map[string]string{
			"R":   "Y",
			"DFI": fp.IE.DFI,
			"T":   fmt.Sprintf("%X", fp.IE.TTL),
			"CD":  fp.IE.CD,
		}
	} else {
		sections["IE"] = map[string]string{"R": "N"}
	}

	return sections
}

// sendOSProbes sends the OS detection probe sequence.
// This is implemented in platform-specific files.
func sendOSProbes(ctx context.Context, laddr, raddr string, openPort, closedPort int, timeout time.Duration) (*OSFingerprint, error) {
	return sendOSProbesImpl(ctx, laddr, raddr, openPort, closedPort, timeout)
}
