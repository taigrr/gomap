package gomap

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// httpTitleScript extracts the HTML <title> from HTTP services.
type httpTitleScript struct{}

func (s *httpTitleScript) ID() string { return "http-title" }
func (s *httpTitleScript) Description() string {
	return "Shows the title of the default page of a web server"
}
func (s *httpTitleScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDefault, CategoryDiscovery, CategorySafe}
}
func (s *httpTitleScript) Phase() ScriptPhase { return PhasePort }
func (s *httpTitleScript) Match(target ScriptTarget) bool {
	svc := strings.ToLower(target.Service)
	return svc == "http" || svc == "https" || svc == "http-proxy" ||
		target.Port == 80 || target.Port == 443 || target.Port == 8080 || target.Port == 8443
}

func (s *httpTitleScript) Run(ctx context.Context, target ScriptTarget) (*ScriptOutput, error) {
	timeout := defaultScriptTimeout
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))

	var conn net.Conn
	var err error

	// Try HTTPS first for port 443/8443, HTTP otherwise
	useHTTPS := target.Port == 443 || target.Port == 8443 || strings.ToLower(target.Service) == "https"

	d := net.Dialer{Timeout: timeout}
	if useHTTPS {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\n\r\n", target.Host)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	body, err := io.ReadAll(io.LimitReader(reader, 64*1024))
	if err != nil && len(body) == 0 {
		return nil, err
	}

	title := extractHTMLTitle(string(body))
	if title == "" {
		return nil, nil // no title found, skip output
	}

	return &ScriptOutput{
		ScriptID: s.ID(),
		Output:   title,
	}, nil
}

func extractHTMLTitle(html string) string {
	lower := strings.ToLower(html)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		start = strings.Index(lower, "<title ")
		if start == -1 {
			return ""
		}
		// Find the closing > of the opening tag
		end := strings.Index(lower[start:], ">")
		if end == -1 {
			return ""
		}
		start += end
	} else {
		start += len("<title>")
	}

	// For simple <title> case
	if strings.HasPrefix(lower[start:], ">") {
		start++
	}

	// Find the actual start after <title>
	idx := strings.Index(lower, "<title>")
	if idx != -1 {
		start = idx + len("<title>")
	}

	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}

	title := strings.TrimSpace(html[start : start+end])
	// Collapse whitespace
	fields := strings.Fields(title)
	return strings.Join(fields, " ")
}

// sshHostKeyScript retrieves the SSH host key fingerprint.
type sshHostKeyScript struct{}

func (s *sshHostKeyScript) ID() string          { return "ssh-hostkey" }
func (s *sshHostKeyScript) Description() string { return "Shows SSH host key information" }
func (s *sshHostKeyScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDefault, CategoryDiscovery, CategorySafe}
}
func (s *sshHostKeyScript) Phase() ScriptPhase { return PhasePort }
func (s *sshHostKeyScript) Match(target ScriptTarget) bool {
	return strings.ToLower(target.Service) == "ssh" || target.Port == 22
}

func (s *sshHostKeyScript) Run(ctx context.Context, target ScriptTarget) (*ScriptOutput, error) {
	timeout := defaultScriptTimeout
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// Read the SSH banner
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	banner = strings.TrimSpace(banner)

	return &ScriptOutput{
		ScriptID: s.ID(),
		Output:   banner,
		Elements: map[string]string{
			"banner": banner,
		},
	}, nil
}

// sslCertScript retrieves basic TLS certificate information.
type sslCertScript struct{}

func (s *sslCertScript) ID() string          { return "ssl-cert" }
func (s *sslCertScript) Description() string { return "Retrieves a server's TLS certificate" }
func (s *sslCertScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDefault, CategoryDiscovery, CategorySafe}
}
func (s *sslCertScript) Phase() ScriptPhase { return PhasePort }
func (s *sslCertScript) Match(target ScriptTarget) bool {
	svc := strings.ToLower(target.Service)
	return svc == "https" || svc == "ssl" || svc == "imaps" || svc == "pop3s" || svc == "smtps" ||
		target.Port == 443 || target.Port == 8443 || target.Port == 993 || target.Port == 995 || target.Port == 465
}

func (s *sslCertScript) Run(ctx context.Context, target ScriptTarget) (*ScriptOutput, error) {
	timeout := defaultScriptTimeout
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))

	d := net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(&d, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil
	}

	cert := state.PeerCertificates[0]

	elements := map[string]string{
		"subject":    cert.Subject.String(),
		"issuer":     cert.Issuer.String(),
		"notBefore":  cert.NotBefore.UTC().Format("2006-01-02T15:04:05"),
		"notAfter":   cert.NotAfter.UTC().Format("2006-01-02T15:04:05"),
		"sigAlgo":    cert.SignatureAlgorithm.String(),
		"version":    fmt.Sprintf("0x%04x", state.Version),
		"cipherName": tls.CipherSuiteName(state.CipherSuite),
	}

	if len(cert.DNSNames) > 0 {
		elements["altNames"] = strings.Join(cert.DNSNames, ", ")
	}

	return &ScriptOutput{
		ScriptID: s.ID(),
		Output:   fmt.Sprintf("Subject: %s / Issuer: %s / Valid: %s to %s", cert.Subject.CommonName, cert.Issuer.CommonName, cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02")),
		Elements: elements,
	}, nil
}
