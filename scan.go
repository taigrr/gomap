package gomap

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanOptions configures a scan.
type ScanOptions struct {
	// ScanType determines the scanning technique (default ConnectScan).
	ScanType ScanType

	// FastScan uses the common port list instead of the detailed list.
	FastScan bool

	// Stealth is a convenience alias that sets ScanType to SYNScan.
	// Deprecated: use ScanType directly.
	Stealth bool

	// Timeout is the per-port connection timeout (default 3s).
	Timeout time.Duration

	// Workers is the number of concurrent scanning goroutines (default auto).
	Workers int

	// ProgressFunc is called after each port is scanned.
	// It receives the number of ports scanned so far and the total.
	// Set to nil to disable progress reporting.
	ProgressFunc func(scanned, total int)

	// Ports specifies custom ports to scan. If nil, the default port list is used.
	Ports []int

	// ProbeFile is an optional path to an nmap-service-probes file.
	// If set, probes are loaded from this file instead of the embedded database.
	// If empty, the embedded probe database is used.
	ProbeFile string

	// PreferIPv6 makes the scanner prefer IPv6 addresses when resolving hostnames.
	PreferIPv6 bool

	// Decoys configures decoy scanning. When set, additional packets are sent
	// from spoofed source IPs to obscure the real scanner. Only works with
	// raw socket scan types (SYN, FIN, Xmas, Null, ACK, Window).
	Decoys *DecoyConfig

	// OpenOnly filters results to only show open ports.
	OpenOnly bool

	// Reason includes the reason a port is in its state.
	Reason bool

	// ExcludeHosts is a list of hosts/CIDRs to skip during range scans.
	ExcludeHosts []string

	// ScanDelay is the minimum delay between probes to the same host.
	ScanDelay time.Duration

	// MaxRetries is the maximum number of port scan probe retransmissions.
	MaxRetries int

	// HostTimeout is the maximum time to spend on a single host.
	HostTimeout time.Duration

	// NoPing skips host discovery and treats all hosts as online (like nmap -Pn).
	NoPing bool

	// NoDNS disables reverse DNS resolution (like nmap -n).
	NoDNS bool

	// AlwaysDNS forces reverse DNS for all IPs (like nmap -R).
	AlwaysDNS bool

	// Verbose enables verbose output.
	Verbose bool

	// SourcePort forces scans to use this source port number.
	SourcePort int

	// MinRate is the minimum packets per second (0 = no minimum).
	MinRate int

	// MaxRate is the maximum packets per second (0 = unlimited).
	MaxRate int

	// VersionIntensity controls service probe depth (0-9, default 7).
	// 0 = light (only NULL probe), 9 = try all probes.
	VersionIntensity int

	// PacketTrace logs every packet sent and received.
	PacketTrace bool

	// OSScanLimit skips OS detection on hosts without at least 1 open + 1 closed port.
	OSScanLimit bool

	// OSScanGuess lowers the OS match confidence threshold for more aggressive guessing.
	OSScanGuess bool

	// MinParallelism is the minimum number of parallel probe groups.
	MinParallelism int

	// MaxParallelism is the maximum number of parallel probe groups.
	MaxParallelism int

	// MinRTTTimeout is the minimum probe round-trip time timeout.
	MinRTTTimeout time.Duration

	// MaxRTTTimeout is the maximum probe round-trip time timeout.
	MaxRTTTimeout time.Duration

	// InitialRTTTimeout is the initial RTT timeout before adaptive adjustment.
	InitialRTTTimeout time.Duration

	// DNSServers overrides the system DNS resolvers.
	DNSServers []string

	// Fragment enables IP fragmentation of probe packets (-f).
	Fragment bool

	// MTU sets the fragment size when Fragment is enabled (default 8).
	MTU int

	// SpoofMAC sets a spoofed MAC address for outgoing packets.
	SpoofMAC string

	// IdleZombie configures the zombie host for idle scanning.
	IdleZombie IdleScanConfig

	// FTPBounce configures the FTP relay for bounce scanning.
	FTPBounce FTPBounceConfig

	// BadSum sends packets with an intentionally incorrect checksum.
	// Useful for detecting firewalls/IDS that don't verify checksums.
	BadSum bool

	// TTL sets the IP time-to-live field on outgoing packets.
	TTL int

	// DataLength pads probe packets with random data to the specified length.
	// Useful for evading IDS that trigger on specific packet sizes.
	DataLength int

	// Output configures file output destinations.
	Output *OutputConfig
}

func (o *ScanOptions) defaults() {
	// Handle Stealth backwards compat
	if o.Stealth && o.ScanType == ConnectScan {
		o.ScanType = SYNScan
	}
	if o.Timeout == 0 {
		o.Timeout = 3 * time.Second
	}
	if o.Workers == 0 {
		if o.FastScan {
			o.Workers = 50
		} else {
			o.Workers = 500
		}
	}
	// Enforce minimum workers for min-rate
	if o.MinRate > 0 || o.MaxRate > 0 {
		rl := NewRateLimiter(o.MinRate, o.MaxRate)
		minW := rl.MinWorkers(o.Timeout)
		if minW > o.Workers {
			o.Workers = minW
		}
	}
	if o.VersionIntensity == 0 && !o.FastScan {
		o.VersionIntensity = 7 // nmap default
	}
}

// protocol returns the appropriate network protocol string for the scan type.
func (o *ScanOptions) protocol() string {
	if o.ScanType == UDPScan {
		return "udp"
	}
	return "tcp"
}

// ScanHost scans a single host for open ports.
func ScanHost(ctx context.Context, hostname string, opts ScanOptions) (*ScanResult, error) {
	opts.defaults()

	// Resolve first to determine address family for local addr
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", hostname, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses for host: %s", hostname)
	}

	// Select preferred address family
	targetIP := selectIP(ips, opts.PreferIPv6)
	laddr, err := GetLocalAddr(targetIP.String())
	if err != nil {
		return nil, fmt.Errorf("getting local IP: %w", err)
	}

	if opts.ScanType.RequiresRawSocket() {
		if !canSocketBind(laddr) {
			return nil, fmt.Errorf("socket: operation not permitted (raw socket required for %s scan)", opts.ScanType)
		}
	}

	if opts.PacketTrace {
		initTraceTimer()
	}

	// Spoof MAC address if requested (Linux only, requires raw sockets)
	if opts.SpoofMAC != "" {
		iface, err := defaultInterface()
		if err != nil {
			return nil, fmt.Errorf("spoof-mac: detecting interface: %w", err)
		}
		restore, err := SpoofMAC(iface, opts.SpoofMAC)
		if err != nil {
			return nil, fmt.Errorf("spoof-mac: %w", err)
		}
		defer restore()
	}

	return scanHostPorts(ctx, hostname, laddr, opts)
}

// ScanRange scans every address on the local CIDR for open ports.
func ScanRange(ctx context.Context, opts ScanOptions) (RangeScanResult, error) {
	opts.defaults()

	laddr, err := GetLocalIP()
	if err != nil {
		return nil, fmt.Errorf("getting local IP: %w", err)
	}

	if opts.ScanType.RequiresRawSocket() {
		if !canSocketBind(laddr) {
			return nil, fmt.Errorf("socket: operation not permitted (raw socket required for %s scan)", opts.ScanType)
		}
	}

	if opts.PacketTrace {
		initTraceTimer()
	}
	if opts.SpoofMAC != "" {
		iface, err := defaultInterface()
		if err != nil {
			return nil, fmt.Errorf("spoof-mac: detecting interface: %w", err)
		}
		restore, err := SpoofMAC(iface, opts.SpoofMAC)
		if err != nil {
			return nil, fmt.Errorf("spoof-mac: %w", err)
		}
		defer restore()
	}

	return scanRange(ctx, laddr, opts)
}

// ScanCIDR scans every address on a given CIDR for open ports.
func ScanCIDR(ctx context.Context, cidr string, opts ScanOptions) (RangeScanResult, error) {
	opts.defaults()

	laddr, err := GetLocalIP()
	if err != nil {
		return nil, fmt.Errorf("getting local IP: %w", err)
	}

	if opts.ScanType.RequiresRawSocket() {
		if !canSocketBind(laddr) {
			return nil, fmt.Errorf("socket: operation not permitted (raw socket required for %s scan)", opts.ScanType)
		}
	}

	if opts.PacketTrace {
		initTraceTimer()
	}
	if opts.SpoofMAC != "" {
		iface, err := defaultInterface()
		if err != nil {
			return nil, fmt.Errorf("spoof-mac: detecting interface: %w", err)
		}
		restore, err := SpoofMAC(iface, opts.SpoofMAC)
		if err != nil {
			return nil, fmt.Errorf("spoof-mac: %w", err)
		}
		defer restore()
	}

	hosts := CreateHostRange(cidr)
	excludeSet := buildExcludeSet(opts.ExcludeHosts)
	var results RangeScanResult

	for _, h := range hosts {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		if excludeSet[h] {
			continue
		}
		if opts.HostTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, opts.HostTimeout)
			defer cancel()
		}
		scan, err := scanHostPorts(ctx, h, laddr, opts)
		if err != nil {
			continue
		}
		results = append(results, scan)
	}

	return results, nil
}

func scanRange(ctx context.Context, laddr string, opts ScanOptions) (RangeScanResult, error) {
	iprange := GetLocalRange()
	hosts := CreateHostRange(iprange)

	var results RangeScanResult
	for _, h := range hosts {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		scan, err := scanHostPorts(ctx, h, laddr, opts)
		if err != nil {
			continue
		}
		results = append(results, scan)
	}

	return results, nil
}

func scanHostPorts(ctx context.Context, hostname, laddr string, opts ScanOptions) (*ScanResult, error) {
	// Resolve the host
	addr, err := net.LookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", hostname, err)
	}

	var hname []string
	if opts.NoDNS {
		hname = []string{hostname}
	} else {
		hname, err = net.LookupAddr(hostname)
		if err != nil {
			if opts.FastScan {
				return nil, fmt.Errorf("reverse lookup %s: %w", hostname, err)
			}
			hname = []string{hostname}
		}
	}

	// Determine ports to scan
	var portList map[int]string
	if len(opts.Ports) > 0 {
		portList = make(map[int]string, len(opts.Ports))
		for _, p := range opts.Ports {
			svc := LookupService(p)
			portList[p] = svc
		}
	} else if opts.FastScan {
		portList = CommonPorts
	} else {
		portList = DetailedPorts
	}

	tasks := len(portList)
	in := make(chan portJob, tasks)
	resultCh := make(chan PortResult, tasks)

	// Feed jobs
	go func() {
		for port, service := range portList {
			select {
			case in <- portJob{port: port, service: service}:
			case <-ctx.Done():
				close(in)
				return
			}
		}
		close(in)
	}()

	// Rate limiter
	var rl *RateLimiter
	if opts.MinRate > 0 || opts.MaxRate > 0 {
		rl = NewRateLimiter(opts.MinRate, opts.MaxRate)
	}

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range in {
				if ctx.Err() != nil {
					return
				}
				if rl != nil {
					rl.Wait()
				}
				scanPort(ctx, resultCh, opts, hostname, laddr, job)
				if opts.ScanDelay > 0 {
					time.Sleep(opts.ScanDelay)
				}
			}
		}()
	}

	// Close results when workers finish
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results
	var results []PortResult
	count := 0
	for result := range resultCh {
		if opts.OpenOnly && !result.Open {
			count++
			if opts.ProgressFunc != nil {
				opts.ProgressFunc(count, tasks)
			}
			continue
		}
		results = append(results, result)
		count++
		if opts.ProgressFunc != nil {
			opts.ProgressFunc(count, tasks)
		}
	}

	return &ScanResult{
		Hostname: hname[0],
		IP:       addr,
		Ports:    results,
	}, nil
}

// buildExcludeSet creates a set of IPs to exclude from scanning.
// Supports both individual IPs and CIDR ranges.
func buildExcludeSet(excludes []string) map[string]bool {
	if len(excludes) == 0 {
		return nil
	}
	set := make(map[string]bool)
	for _, e := range excludes {
		if strings.Contains(e, "/") {
			for _, ip := range CreateHostRange(e) {
				set[ip] = true
			}
		} else {
			set[e] = true
		}
	}
	return set
}

type portJob struct {
	port    int
	service string
}

// scanPort dispatches a port scan to the appropriate scanner based on scan type.
func scanPort(ctx context.Context, resultCh chan<- PortResult, opts ScanOptions, hostname, laddr string, job portJob) {
	// Send decoy packets for raw scan types
	if opts.Decoys != nil && opts.ScanType.RequiresRawSocket() {
		sendDecoyPackets(ctx, opts, hostname, job.port, laddr)
	}

	// Use fragmented packets if requested
	if opts.Fragment && opts.ScanType.RequiresRawSocket() {
		sport := uint16(randomPort(10000, 65535))
		flags := tcpSYN
		switch opts.ScanType {
		case FINScan:
			flags = tcpFIN
		case XmasScan:
			flags = tcpFIN | tcpPSH | tcpURG
		case NullScan:
			flags = 0
		case ACKScan, WindowScan:
			flags = tcpACK
		case MaimonScan:
			flags = tcpFIN | tcpACK
		}
		_ = sendFragmentedPacket(laddr, hostname, sport, uint16(job.port), flags, opts.MTU)
	}

	// Trace raw scan packets at the dispatch level
	if opts.PacketTrace && opts.ScanType != ConnectScan && opts.ScanType != UDPScan {
		flagStr := tcpFlagString(opts.ScanType)
		tracePacket(PacketSent, "TCP", laddr, 0, hostname, job.port, flagStr)
	}

	switch opts.ScanType {
	case ConnectScan:
		scanPortConnect(ctx, resultCh, opts.protocol(), hostname, job.service, job.port, opts.Timeout, opts.PacketTrace)
	case SYNScan:
		scanPortSyn(ctx, resultCh, opts.protocol(), hostname, job.service, job.port, laddr, opts.Timeout)
	case FINScan:
		scanPortRaw(ctx, resultCh, hostname, job.service, job.port, laddr, tcpFIN, opts.Timeout)
	case XmasScan:
		scanPortRaw(ctx, resultCh, hostname, job.service, job.port, laddr, tcpFIN|tcpPSH|tcpURG, opts.Timeout)
	case NullScan:
		scanPortRaw(ctx, resultCh, hostname, job.service, job.port, laddr, 0, opts.Timeout)
	case ACKScan:
		scanPortACK(ctx, resultCh, hostname, job.service, job.port, laddr, opts.Timeout)
	case WindowScan:
		scanPortWindow(ctx, resultCh, hostname, job.service, job.port, laddr, opts.Timeout)
	case MaimonScan:
		scanPortRaw(ctx, resultCh, hostname, job.service, job.port, laddr, tcpFIN|tcpACK, opts.Timeout)
	case UDPScan:
		scanPortUDP(ctx, resultCh, hostname, job.service, job.port, opts.Timeout, opts.PacketTrace)
	case SCTPInitScan:
		scanPortSCTPInit(ctx, resultCh, hostname, job.service, job.port, laddr, opts.Timeout)
	case SCTPCookieEchoScan:
		scanPortSCTPCookieEcho(ctx, resultCh, hostname, job.service, job.port, laddr, opts.Timeout)
	case IdleScan:
		scanPortIdle(ctx, resultCh, hostname, job.service, job.port, laddr, opts.Timeout, opts.IdleZombie)
	case FTPBounceScan:
		scanPortFTPBounce(ctx, resultCh, hostname, job.service, job.port, opts.Timeout, opts.FTPBounce)
	default:
		scanPortConnect(ctx, resultCh, "tcp", hostname, job.service, job.port, opts.Timeout, opts.PacketTrace)
	}
}

// sendDecoyPackets sends scan packets from each decoy IP.
// These are "noise" packets that make it harder to identify the real scanner.
func sendDecoyPackets(ctx context.Context, opts ScanOptions, hostname string, port int, realAddr string) {
	flags := tcpSYN // default
	switch opts.ScanType {
	case FINScan:
		flags = tcpFIN
	case XmasScan:
		flags = tcpFIN | tcpPSH | tcpURG
	case NullScan:
		flags = 0
	case ACKScan, WindowScan:
		flags = tcpACK
	case MaimonScan:
		flags = tcpFIN | tcpACK
	}

	for _, decoyIP := range opts.Decoys.ResolvedIPs() {
		if ctx.Err() != nil {
			return
		}
		addr := decoyIP.String()
		if addr == realAddr {
			continue // skip real IP, it sends its own packet
		}
		sport := uint16(randomPort(10000, 65535))
		// Best-effort: ignore errors from decoy packets
		sendTCPPacket(addr, hostname, sport, uint16(port), flags)
	}
}

// scanPortConnect performs a full TCP connect() scan on a single port.
func scanPortConnect(ctx context.Context, resultCh chan<- PortResult, protocol, hostname, service string, port int, timeout time.Duration, packetTrace bool) {
	result := PortResult{Port: port, Service: service}

	if packetTrace {
		traceConnect(PacketSent, strings.ToUpper(protocol), hostname, port, "connect()")
	}

	// Use a dialer that respects context
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, protocol, net.JoinHostPort(hostname, strconv.Itoa(port)))
	if err != nil {
		if packetTrace {
			traceConnect(PacketReceived, strings.ToUpper(protocol), hostname, port, err.Error())
		}
		if ctx.Err() != nil {
			result.State = PortFiltered
			result.Reason = "no-response"
		} else {
			result.State = PortClosed
			result.Reason = "conn-refused"
		}
		resultCh <- result
		return
	}
	conn.Close()
	if packetTrace {
		traceConnect(PacketReceived, strings.ToUpper(protocol), hostname, port, "Connected")
	}
	result.Open = true
	result.State = PortOpen
	result.Reason = "syn-ack"
	resultCh <- result
}

// scanPortUDP sends an empty UDP packet and listens for ICMP unreachable.
// No response = open|filtered, ICMP unreachable = closed.
func scanPortUDP(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, timeout time.Duration, packetTrace bool) {
	result := PortResult{Port: port, Service: service}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(hostname, strconv.Itoa(port)))
	if err != nil {
		result.State = PortFiltered
		resultCh <- result
		return
	}
	defer conn.Close()

	// Send empty UDP packet
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}
	conn.SetDeadline(deadline)

	if packetTrace {
		tracePacket(PacketSent, "UDP", "", 0, hostname, port, "")
	}

	_, err = conn.Write([]byte{})
	if err != nil {
		result.State = PortFiltered
		resultCh <- result
		return
	}

	// Try to read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		if ctx.Err() != nil {
			result.State = PortFiltered
			resultCh <- result
			return
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.State = PortOpenFiltered
			result.Open = true
			resultCh <- result
			return
		}
		if packetTrace {
			tracePacket(PacketReceived, "UDP", hostname, port, "", 0, "port-unreachable")
		}
		result.State = PortClosed
		resultCh <- result
		return
	}

	if packetTrace {
		tracePacket(PacketReceived, "UDP", hostname, port, "", 0, fmt.Sprintf("len=%d", n))
	}
	result.Open = true
	result.State = PortOpen
	resultCh <- result
}
