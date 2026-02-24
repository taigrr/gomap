package gomap

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/taigrr/gomap/probedb"
)

// ServiceVersion contains the result of service version detection.
type ServiceVersion struct {
	Port        int
	Service     string
	Banner      string
	Version     string
	ProductName string
	Info        string
	OS          string
	DeviceType  string
	CPE         []string
}

// GrabBanner connects to a port and attempts service identification using
// the nmap-compatible probe database. It sends protocol-specific probes
// and matches responses against known service signatures.
//
// If probeDB is nil, the embedded probe database is used.
func GrabBanner(ctx context.Context, host string, port int, timeout time.Duration, probeDB *probedb.ServiceProbeDB) (*ServiceVersion, error) {
	return GrabBannerWithIntensity(ctx, host, port, timeout, probeDB, 7)
}

// GrabBannerWithIntensity is like GrabBanner but with configurable probe intensity.
func GrabBannerWithIntensity(ctx context.Context, host string, port int, timeout time.Duration, probeDB *probedb.ServiceProbeDB, intensity int) (*ServiceVersion, error) {
	if probeDB == nil {
		var err error
		probeDB, err = DefaultProbeDB()
		if err != nil {
			// Fall back to simple banner grab if no probe DB
			return grabBannerSimple(ctx, host, port, timeout)
		}
	}

	probes := probeDB.ProbesForPort(port, "TCP")
	if len(probes) == 0 {
		return grabBannerSimple(ctx, host, port, timeout)
	}

	// Limit probes by intensity: intensity 0 = only NULL probe,
	// intensity 9 = all probes. Scale linearly.
	if intensity < 9 && len(probes) > 1 {
		maxProbes := 1 + (len(probes)-1)*intensity/9
		if maxProbes < 1 {
			maxProbes = 1
		}
		if maxProbes < len(probes) {
			probes = probes[:maxProbes]
		}
	}

	for _, probe := range probes {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		sv, err := sendProbe(ctx, host, port, probe, timeout)
		if err != nil {
			continue
		}
		if sv != nil {
			return sv, nil
		}
	}

	// No probe matched — try simple banner grab as last resort
	return grabBannerSimple(ctx, host, port, timeout)
}

// GrabBanners performs service version detection on all open ports in a scan result.
// If opts.ProbeFile is set, probes are loaded from that file; otherwise the
// embedded database is used.
func GrabBanners(ctx context.Context, host string, result *ScanResult, opts ScanOptions) []ServiceVersion {
	db, err := loadProbeDB(opts.ProbeFile)
	if err != nil {
		db = nil // will fall back to simple grabs
	}

	var versions []ServiceVersion
	for _, p := range result.Ports {
		if !p.Open {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		if opts.VersionTraceWriter != nil {
			fmt.Fprintf(opts.VersionTraceWriter, "VERSION TRACE: Probing %s:%d (intensity %d)\n", host, p.Port, opts.VersionIntensity)
		}
		sv, err := GrabBannerWithIntensity(ctx, host, p.Port, opts.Timeout, db, opts.VersionIntensity)
		if err != nil {
			if opts.VersionTraceWriter != nil {
				fmt.Fprintf(opts.VersionTraceWriter, "VERSION TRACE: %s:%d failed: %v\n", host, p.Port, err)
			}
			continue
		}
		if sv != nil && (sv.Banner != "" || sv.Service != "") {
			versions = append(versions, *sv)
		}
	}
	return versions
}

// loadProbeDB loads the probe database from a file or returns the embedded default.
func loadProbeDB(probeFile string) (*probedb.ServiceProbeDB, error) {
	if probeFile != "" {
		return probedb.LoadServiceProbesFile(probeFile)
	}
	return DefaultProbeDB()
}

// sendProbe sends a single probe to a host:port and checks matches.
func sendProbe(ctx context.Context, host string, port int, probe probedb.ServiceProbe, timeout time.Duration) (*ServiceVersion, error) {
	waitMS := probe.TotalWaitMS
	if waitMS == 0 {
		waitMS = 5000
	}
	probeTimeout := time.Duration(waitMS) * time.Millisecond
	if probeTimeout > timeout {
		probeTimeout = timeout
	}

	d := net.Dialer{Timeout: probeTimeout}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(probeTimeout)
	}

	// Send probe string (NULL probe sends nothing)
	if len(probe.ProbeString) > 0 {
		conn.SetWriteDeadline(deadline)
		if _, err := conn.Write(probe.ProbeString); err != nil {
			return nil, err
		}
	}

	// Read response
	conn.SetReadDeadline(deadline)
	reader := bufio.NewReaderSize(conn, 4096)
	buf := make([]byte, 4096)
	n, _ := reader.Read(buf)
	if n == 0 {
		return nil, nil // no response
	}

	response := buf[:n]
	responseStr := string(response)

	// Try matches first (hard matches are definitive)
	for _, m := range probe.Matches {
		submatches := m.Pattern.FindStringSubmatch(responseStr)
		if submatches != nil {
			vi := m.VersionInfo.Apply(submatches)
			return &ServiceVersion{
				Port:        port,
				Service:     m.Service,
				Banner:      strings.TrimSpace(responseStr),
				ProductName: vi.ProductName,
				Version:     vi.Version,
				Info:        vi.Info,
				OS:          vi.OS,
				DeviceType:  vi.DeviceType,
				CPE:         vi.CPE,
			}, nil
		}
	}

	// Try soft matches (less confident, keep trying other probes)
	for _, m := range probe.SoftMatches {
		submatches := m.Pattern.FindStringSubmatch(responseStr)
		if submatches != nil {
			vi := m.VersionInfo.Apply(submatches)
			return &ServiceVersion{
				Port:        port,
				Service:     m.Service,
				Banner:      strings.TrimSpace(responseStr),
				ProductName: vi.ProductName,
				Version:     vi.Version,
				Info:        vi.Info,
				OS:          vi.OS,
				DeviceType:  vi.DeviceType,
				CPE:         vi.CPE,
			}, nil
		}
	}

	return nil, nil // no match
}

// grabBannerSimple is the fallback banner grabber when no probe database is available.
func grabBannerSimple(ctx context.Context, host string, port int, timeout time.Duration) (*ServiceVersion, error) {
	d := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}
	conn.SetReadDeadline(deadline)

	reader := bufio.NewReaderSize(conn, 4096)
	banner, err := reader.ReadString('\n')
	if err != nil {
		if len(banner) == 0 {
			buf := make([]byte, 4096)
			n, _ := reader.Read(buf)
			banner = string(buf[:n])
		}
	}

	banner = strings.TrimSpace(banner)
	if banner == "" {
		// Try sending a basic probe
		conn.SetWriteDeadline(deadline)
		conn.Write([]byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"))
		conn.SetReadDeadline(deadline)
		buf := make([]byte, 4096)
		n, _ := reader.Read(buf)
		banner = strings.TrimSpace(string(buf[:n]))
	}

	if banner == "" {
		return nil, nil
	}

	sv := &ServiceVersion{
		Port:    port,
		Banner:  banner,
		Service: identifyServiceSimple(port, banner),
		Version: extractVersionSimple(banner),
	}

	return sv, nil
}

// identifyServiceSimple identifies the service from the banner text (fallback).
func identifyServiceSimple(port int, banner string) string {
	lbanner := strings.ToLower(banner)

	switch {
	case strings.HasPrefix(banner, "SSH-"):
		return "ssh"
	case strings.HasPrefix(banner, "220"):
		if strings.Contains(lbanner, "ftp") {
			return "ftp"
		}
		if strings.Contains(lbanner, "smtp") || strings.Contains(lbanner, "mail") {
			return "smtp"
		}
		return "ftp-or-smtp"
	case strings.HasPrefix(banner, "HTTP/"):
		return "http"
	case strings.HasPrefix(banner, "+OK"):
		return "pop3"
	case strings.HasPrefix(banner, "* OK"):
		return "imap"
	case strings.Contains(lbanner, "mysql"):
		return "mysql"
	case strings.Contains(lbanner, "postgresql"):
		return "postgresql"
	case strings.Contains(lbanner, "redis"):
		return "redis"
	case strings.Contains(lbanner, "memcached"):
		return "memcached"
	case strings.HasPrefix(banner, "+PONG"):
		return "redis"
	default:
		return LookupService(port)
	}
}

// extractVersionSimple tries to extract a version string from a banner (fallback).
func extractVersionSimple(banner string) string {
	if banner == "" {
		return ""
	}

	if strings.HasPrefix(banner, "SSH-") {
		parts := strings.SplitN(banner, " ", 2)
		if len(parts) > 0 {
			return strings.TrimPrefix(parts[0], "SSH-2.0-")
		}
	}

	if strings.HasPrefix(banner, "HTTP/") {
		return banner
	}

	return ""
}
