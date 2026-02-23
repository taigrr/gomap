package gomap

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// ServiceVersion contains the result of service version detection.
type ServiceVersion struct {
	Port    int
	Service string
	Banner  string
	Version string
}

// GrabBanner connects to a port and reads the initial banner.
// Many services (SSH, SMTP, FTP, etc.) send a banner on connect.
func GrabBanner(ctx context.Context, host string, port int, timeout time.Duration) (*ServiceVersion, error) {
	d := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()

	// Set read deadline
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}
	conn.SetReadDeadline(deadline)

	// Read banner (first line or up to 4KB)
	reader := bufio.NewReaderSize(conn, 4096)
	banner, err := reader.ReadString('\n')
	if err != nil {
		// Some services don't send a newline — read what we can
		if len(banner) == 0 {
			buf := make([]byte, 4096)
			n, _ := reader.Read(buf)
			banner = string(buf[:n])
		}
	}

	banner = strings.TrimSpace(banner)
	if banner == "" {
		// Try sending a probe for services that need stimulation
		banner = probeService(ctx, conn, port, deadline)
	}

	sv := &ServiceVersion{
		Port:    port,
		Banner:  banner,
		Service: identifyService(port, banner),
		Version: extractVersion(banner),
	}

	return sv, nil
}

// GrabBanners performs banner grabbing on all open ports in a scan result.
func GrabBanners(ctx context.Context, host string, result *ScanResult, timeout time.Duration) []ServiceVersion {
	var versions []ServiceVersion
	for _, p := range result.Ports {
		if !p.Open {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		sv, err := GrabBanner(ctx, host, p.Port, timeout)
		if err != nil {
			continue
		}
		if sv.Banner != "" || sv.Service != "" {
			versions = append(versions, *sv)
		}
	}
	return versions
}

// probeService sends a protocol-specific probe for services that don't
// send banners on connect (HTTP, etc.).
func probeService(ctx context.Context, conn net.Conn, port int, deadline time.Time) string {
	if ctx.Err() != nil {
		return ""
	}

	var probe string
	switch port {
	case 80, 443, 8080, 8443, 8000, 8008, 8081, 8888, 3000:
		probe = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
	case 6379:
		probe = "PING\r\n"
	case 11211:
		probe = "version\r\n"
	case 27017:
		// MongoDB wire protocol hello
		return ""
	default:
		probe = "\r\n"
	}

	conn.SetWriteDeadline(deadline)
	conn.Write([]byte(probe))

	conn.SetReadDeadline(deadline)
	reader := bufio.NewReaderSize(conn, 4096)
	response, _ := reader.ReadString('\n')
	return strings.TrimSpace(response)
}

// identifyService identifies the service from the banner text.
func identifyService(port int, banner string) string {
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
		// Fall back to port-based lookup
		return LookupService(port)
	}
}

// extractVersion tries to extract a version string from a banner.
func extractVersion(banner string) string {
	if banner == "" {
		return ""
	}

	// SSH: "SSH-2.0-OpenSSH_8.9p1"
	if strings.HasPrefix(banner, "SSH-") {
		parts := strings.SplitN(banner, " ", 2)
		if len(parts) > 0 {
			return strings.TrimPrefix(parts[0], "SSH-2.0-")
		}
	}

	// HTTP: "HTTP/1.1 200 OK" — the version is in the Server header, not the status line
	if strings.HasPrefix(banner, "HTTP/") {
		return banner
	}

	return ""
}
