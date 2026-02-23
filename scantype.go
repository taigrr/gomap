package gomap

// ScanType represents the type of port scan to perform.
type ScanType int

const (
	// ConnectScan performs a full TCP connect() scan.
	// Works on all platforms, no special privileges required.
	ConnectScan ScanType = iota

	// SYNScan performs a half-open SYN scan (stealth scan).
	// Linux only, requires raw socket privileges (root/CAP_NET_RAW).
	SYNScan

	// FINScan sends a TCP FIN packet. Open ports typically don't respond,
	// while closed ports respond with RST. Useful for evading firewalls.
	// Linux only, requires raw socket privileges.
	FINScan

	// XmasScan sends a TCP packet with FIN, PSH, and URG flags set.
	// Similar to FIN scan but with more flags lit up like a Christmas tree.
	// Linux only, requires raw socket privileges.
	XmasScan

	// NullScan sends a TCP packet with no flags set.
	// Closed ports respond with RST; open/filtered ports don't respond.
	// Linux only, requires raw socket privileges.
	NullScan

	// ACKScan sends a TCP ACK packet. Used to map firewall rules.
	// Doesn't determine open/closed, but filtered/unfiltered.
	// Linux only, requires raw socket privileges.
	ACKScan

	// WindowScan is like ACK scan but examines the TCP window field
	// of RST packets to differentiate open from closed ports.
	// Linux only, requires raw socket privileges.
	WindowScan

	// UDPScan sends UDP packets and interprets ICMP responses.
	// Works cross-platform but may require privileges for ICMP listening.
	UDPScan
)

// String returns the human-readable name of a scan type.
func (s ScanType) String() string {
	switch s {
	case ConnectScan:
		return "connect"
	case SYNScan:
		return "syn"
	case FINScan:
		return "fin"
	case XmasScan:
		return "xmas"
	case NullScan:
		return "null"
	case ACKScan:
		return "ack"
	case WindowScan:
		return "window"
	case UDPScan:
		return "udp"
	default:
		return "unknown"
	}
}

// RequiresRawSocket returns true if the scan type requires raw socket access.
func (s ScanType) RequiresRawSocket() bool {
	switch s {
	case SYNScan, FINScan, XmasScan, NullScan, ACKScan, WindowScan:
		return true
	default:
		return false
	}
}

// PortState represents the state of a scanned port.
type PortState int

const (
	// PortClosed indicates the port is closed (RST received).
	PortClosed PortState = iota

	// PortOpen indicates the port is open (connection accepted or SYN-ACK received).
	PortOpen

	// PortFiltered indicates the port is filtered (no response or ICMP unreachable).
	PortFiltered

	// PortUnfiltered indicates the port responded but open/closed is unknown (ACK scan).
	PortUnfiltered

	// PortOpenFiltered indicates the port is either open or filtered (no response in FIN/NULL/Xmas).
	PortOpenFiltered
)

// String returns the human-readable name of a port state.
func (s PortState) String() string {
	switch s {
	case PortClosed:
		return "closed"
	case PortOpen:
		return "open"
	case PortFiltered:
		return "filtered"
	case PortUnfiltered:
		return "unfiltered"
	case PortOpenFiltered:
		return "open|filtered"
	default:
		return "unknown"
	}
}
