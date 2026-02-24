package gomap

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
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

	// PacketTrace logs every packet sent and received to TraceWriter.
	// If TraceWriter is nil and PacketTrace is true, os.Stderr is used.
	PacketTrace bool

	// TraceWriter receives packet trace output. If nil and PacketTrace is true,
	// defaults to os.Stderr. Library users should set this to avoid side effects.
	TraceWriter io.Writer

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

	// ScanFlags sets custom TCP flags for raw scans (--scanflags).
	// When set, overrides the flags implied by the scan type.
	ScanFlags uint16

	// ScanFlagsSet indicates whether ScanFlags was explicitly provided.
	ScanFlagsSet bool

	// SpoofSourceIP spoofs the source IP address (-S).
	// Only effective with raw socket scan types on Linux.
	SpoofSourceIP string

	// Proxies is a list of HTTP/SOCKS4 proxy URLs to relay connect scans through.
	Proxies []string

	// Data is arbitrary hex data to append to sent packets (--data).
	Data []byte

	// DataString is an ASCII string to append to sent packets (--data-string).
	DataString string

	// IPOptions sets raw IP options on outgoing packets (--ip-options).
	IPOptions []byte

	// MaxOSTries limits the number of OS detection attempts per host.
	MaxOSTries int

	// VersionTrace enables detailed tracing of service version detection.
	// Output goes to VersionTraceWriter (defaults to os.Stderr).
	VersionTrace bool

	// VersionTraceWriter receives version trace output. If nil and VersionTrace
	// is true, defaults to os.Stderr. Library users should set this to avoid side effects.
	VersionTraceWriter io.Writer

	// ScriptArgs provides arguments to scripts as key=value pairs.
	ScriptArgs map[string]string

	// ScriptTrace enables tracing of all script data sent/received.
	ScriptTrace bool

	// ExcludePorts is a list of port numbers to exclude from scanning.
	ExcludePorts []int

	// MinHostgroup sets the minimum number of hosts to scan in parallel.
	MinHostgroup int

	// MaxHostgroup sets the maximum number of hosts to scan in parallel.
	MaxHostgroup int

	// Output configures file output destinations.
	Output *OutputConfig
}

// Validate checks that the scan options are consistent and returns an error
// describing any problems. This is called automatically by Scan* functions,
// but callers may invoke it early for fast feedback.
func (o *ScanOptions) Validate() error {
	// Check option consistency first (cheapest checks)
	if o.VersionIntensity < 0 || o.VersionIntensity > 9 {
		return fmt.Errorf("%w: version-intensity must be 0-9, got %d", ErrInvalidScanOptions, o.VersionIntensity)
	}
	if o.MaxRate > 0 && o.MinRate > 0 && o.MinRate > o.MaxRate {
		return fmt.Errorf("%w: min-rate (%d) cannot exceed max-rate (%d)", ErrInvalidScanOptions, o.MinRate, o.MaxRate)
	}
	if o.Workers < 0 {
		return fmt.Errorf("%w: workers must be >= 0", ErrInvalidScanOptions)
	}
	if o.ScanType == IdleScan && o.IdleZombie.ZombieHost == "" {
		return fmt.Errorf("%w: idle scan requires --idle-zombie", ErrInvalidScanOptions)
	}
	if o.ScanType == FTPBounceScan && o.FTPBounce.Server == "" {
		return fmt.Errorf("%w: FTP bounce scan requires --ftp-bounce", ErrInvalidScanOptions)
	}

	// Check privileges last (may involve syscalls)
	if o.ScanType.RequiresRawSocket() {
		if laddr, err := GetLocalIP(); err == nil {
			if !canSocketBind(laddr) {
				return fmt.Errorf("%w: %s scan needs root or CAP_NET_RAW", ErrRawSocketRequired, o.ScanType)
			}
		}
	}
	return nil
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
	if o.PacketTrace && o.TraceWriter == nil {
		o.TraceWriter = os.Stderr
	}
	if o.VersionTrace && o.VersionTraceWriter == nil {
		o.VersionTraceWriter = os.Stderr
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
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrResolveHost, hostname, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoAddresses, hostname)
	}

	// Select preferred address family
	targetIP := selectIP(ips, opts.PreferIPv6)
	laddr, err := GetLocalAddr(targetIP.String())
	if err != nil {
		return nil, fmt.Errorf("getting local IP: %w", err)
	}

	if opts.ScanType.RequiresRawSocket() {
		if !canSocketBind(laddr) {
			return nil, fmt.Errorf("%w: %s scan needs root or CAP_NET_RAW", ErrRawSocketRequired, opts.ScanType)
		}
	}

	tr := newTracer(opts.TraceWriter)

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

	return scanHostPorts(ctx, hostname, laddr, opts, tr)
}

// ScanRange scans every address on the local CIDR for open ports.
func ScanRange(ctx context.Context, opts ScanOptions) (RangeScanResult, error) {
	opts.defaults()

	if err := opts.Validate(); err != nil {
		return nil, err
	}

	laddr, err := GetLocalIP()
	if err != nil {
		return nil, fmt.Errorf("getting local IP: %w", err)
	}

	tr := newTracer(opts.TraceWriter)

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

	return scanRange(ctx, laddr, opts, tr)
}

// ScanCIDR scans every address on a given CIDR for open ports.
func ScanCIDR(ctx context.Context, cidr string, opts ScanOptions) (RangeScanResult, error) {
	opts.defaults()

	if err := opts.Validate(); err != nil {
		return nil, err
	}

	laddr, err := GetLocalIP()
	if err != nil {
		return nil, fmt.Errorf("getting local IP: %w", err)
	}

	tr := newTracer(opts.TraceWriter)

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
		hostCtx := ctx
		var cancel context.CancelFunc
		if opts.HostTimeout > 0 {
			hostCtx, cancel = context.WithTimeout(ctx, opts.HostTimeout)
		}
		scan, err := scanHostPorts(hostCtx, h, laddr, opts, tr)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			continue
		}
		results = append(results, scan)
	}

	return results, nil
}

func scanRange(ctx context.Context, laddr string, opts ScanOptions, tr *tracer) (RangeScanResult, error) {
	iprange := GetLocalRange()
	hosts := CreateHostRange(iprange)

	var results RangeScanResult
	for _, h := range hosts {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		hostCtx := ctx
		var cancel context.CancelFunc
		if opts.HostTimeout > 0 {
			hostCtx, cancel = context.WithTimeout(ctx, opts.HostTimeout)
		}
		scan, err := scanHostPorts(hostCtx, h, laddr, opts, tr)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			continue
		}
		results = append(results, scan)
	}

	return results, nil
}

func scanHostPorts(ctx context.Context, hostname, laddr string, opts ScanOptions, tr *tracer) (*ScanResult, error) {
	startTime := time.Now()

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
			hname = []string{hostname}
		}
	}

	// Determine ports to scan
	portList := resolvePortList(opts)

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
					rl.WaitCtx(ctx)
				}
				scanPort(ctx, resultCh, opts, hostname, laddr, job, tr)
				if opts.ScanDelay > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(opts.ScanDelay):
					}
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

	endTime := time.Now()

	// Set protocol on results
	proto := opts.protocol()
	for i := range results {
		if results[i].Protocol == "" {
			results[i].Protocol = proto
		}
	}

	return &ScanResult{
		Hostname:  hname[0],
		IP:        addr,
		Ports:     results,
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  endTime.Sub(startTime),
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

// scanTypeFlags returns the default TCP flags for a scan type.
func scanTypeFlags(st ScanType) uint16 {
	switch st {
	case SYNScan:
		return tcpSYN
	case FINScan:
		return tcpFIN
	case XmasScan:
		return tcpFIN | tcpPSH | tcpURG
	case NullScan:
		return 0
	case ACKScan, WindowScan:
		return tcpACK
	case MaimonScan:
		return tcpFIN | tcpACK
	default:
		return tcpSYN
	}
}

type portJob struct {
	port    int
	service string
}

// scanPort dispatches a port scan to the appropriate scanner based on scan type.
func scanPort(ctx context.Context, resultCh chan<- PortResult, opts ScanOptions, hostname, laddr string, job portJob, tr *tracer) {
	// Send decoy packets for raw scan types
	if opts.Decoys != nil && opts.ScanType.RequiresRawSocket() {
		sendDecoyPackets(ctx, opts, hostname, job.port, laddr)
	}

	// Resolve effective TCP flags (--scanflags overrides scan type)
	effectiveFlags := scanTypeFlags(opts.ScanType)
	if opts.ScanFlagsSet {
		effectiveFlags = opts.ScanFlags
	}

	// Use fragmented packets if requested
	if opts.Fragment && opts.ScanType.RequiresRawSocket() {
		sport := uint16(randomPort(10000, 65535))
		_ = sendFragmentedPacket(laddr, hostname, sport, uint16(job.port), effectiveFlags, opts.MTU)
	}

	// Trace raw scan packets at the dispatch level
	if tr != nil && opts.ScanType != ConnectScan && opts.ScanType != UDPScan {
		flagStr := tcpFlagString(opts.ScanType)
		if opts.ScanFlagsSet {
			flagStr = fmt.Sprintf("0x%02x", opts.ScanFlags)
		}
		tr.tracePacket(PacketSent, "TCP", laddr, 0, hostname, job.port, flagStr)
	}

	// --scanflags with a raw scan type: use custom flags via scanPortRaw
	if opts.ScanFlagsSet && opts.ScanType.RequiresRawSocket() {
		scanPortRaw(ctx, resultCh, hostname, job.service, job.port, laddr, opts.ScanFlags, opts.Timeout)
		return
	}

	switch opts.ScanType {
	case ConnectScan:
		if len(opts.Proxies) > 0 {
			scanPortProxy(ctx, resultCh, hostname, job.service, job.port, opts.Timeout, opts.Proxies, tr)
		} else {
			scanPortConnect(ctx, resultCh, opts.protocol(), hostname, job.service, job.port, opts.Timeout, tr)
		}
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
		scanPortUDP(ctx, resultCh, hostname, job.service, job.port, opts.Timeout, tr)
	case SCTPInitScan:
		scanPortSCTPInit(ctx, resultCh, hostname, job.service, job.port, laddr, opts.Timeout)
	case SCTPCookieEchoScan:
		scanPortSCTPCookieEcho(ctx, resultCh, hostname, job.service, job.port, laddr, opts.Timeout)
	case IdleScan:
		scanPortIdle(ctx, resultCh, hostname, job.service, job.port, laddr, opts.Timeout, opts.IdleZombie)
	case FTPBounceScan:
		scanPortFTPBounce(ctx, resultCh, hostname, job.service, job.port, opts.Timeout, opts.FTPBounce)
	default:
		scanPortConnect(ctx, resultCh, "tcp", hostname, job.service, job.port, opts.Timeout, tr)
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
func scanPortConnect(ctx context.Context, resultCh chan<- PortResult, protocol, hostname, service string, port int, timeout time.Duration, tr *tracer) {
	result := PortResult{Port: port, Service: service}

	tr.traceConnect(PacketSent, strings.ToUpper(protocol), hostname, port, "connect()")

	// Use a dialer that respects context
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, protocol, net.JoinHostPort(hostname, strconv.Itoa(port)))
	if err != nil {
		tr.traceConnect(PacketReceived, strings.ToUpper(protocol), hostname, port, err.Error())
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
	tr.traceConnect(PacketReceived, strings.ToUpper(protocol), hostname, port, "Connected")
	result.Open = true
	result.State = PortOpen
	result.Reason = "syn-ack"
	resultCh <- result
}

// scanPortUDP sends an empty UDP packet and listens for ICMP unreachable.
// No response = open|filtered, ICMP unreachable = closed.
func scanPortUDP(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, timeout time.Duration, tr *tracer) {
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

	tr.tracePacket(PacketSent, "UDP", "", 0, hostname, port, "")

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
		tr.tracePacket(PacketReceived, "UDP", hostname, port, "", 0, "port-unreachable")
		result.State = PortClosed
		resultCh <- result
		return
	}

	tr.tracePacket(PacketReceived, "UDP", hostname, port, "", 0, fmt.Sprintf("len=%d", n))
	result.Open = true
	result.State = PortOpen
	resultCh <- result
}
