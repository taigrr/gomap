package gomap

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

func init() {
	DefaultEngine.Register(&smtpCommandsScript{})
	DefaultEngine.Register(&ftpAnonScript{})
	DefaultEngine.Register(&mysqlInfoScript{})
	DefaultEngine.Register(&redisInfoScript{})
	DefaultEngine.Register(&httpHeadersScript{})
	DefaultEngine.Register(&httpRobotsScript{})
	DefaultEngine.Register(&bannerScript{})
}

// smtpCommandsScript queries SMTP for supported commands (EHLO).
type smtpCommandsScript struct{}

func (s *smtpCommandsScript) ID() string          { return "smtp-commands" }
func (s *smtpCommandsScript) Description() string { return "Retrieves SMTP server supported commands via EHLO" }
func (s *smtpCommandsScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDefault, CategoryDiscovery, CategorySafe}
}
func (s *smtpCommandsScript) Phase() ScriptPhase { return PhasePort }
func (s *smtpCommandsScript) Match(target ScriptTarget) bool {
	svc := strings.ToLower(target.Service)
	return svc == "smtp" || svc == "submission" || target.Port == 25 || target.Port == 587 || target.Port == 465
}

func (s *smtpCommandsScript) Run(ctx context.Context, target ScriptTarget) (*ScriptOutput, error) {
	timeout := 5 * time.Second
	addr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// Read banner
	banner, _ := reader.ReadString('\n')
	banner = strings.TrimSpace(banner)

	// Send EHLO
	fmt.Fprintf(conn, "EHLO gomap\r\n")

	var commands []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if len(line) < 4 {
			break
		}
		// Extract command from "250-COMMAND" or "250 COMMAND"
		cmd := line[4:]
		if idx := strings.Index(cmd, " "); idx > 0 {
			cmd = cmd[:idx]
		}
		commands = append(commands, cmd)
		if line[3] == ' ' {
			break // last line
		}
	}

	fmt.Fprintf(conn, "QUIT\r\n")

	if len(commands) == 0 {
		return nil, nil
	}

	return &ScriptOutput{
		ScriptID: s.ID(),
		Output:   strings.Join(commands, " "),
		Elements: map[string]string{
			"banner":   banner,
			"commands": strings.Join(commands, ", "),
		},
	}, nil
}

// ftpAnonScript checks if anonymous FTP login is allowed.
type ftpAnonScript struct{}

func (s *ftpAnonScript) ID() string          { return "ftp-anon" }
func (s *ftpAnonScript) Description() string { return "Checks whether FTP allows anonymous login" }
func (s *ftpAnonScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDefault, CategoryAuth, CategorySafe}
}
func (s *ftpAnonScript) Phase() ScriptPhase { return PhasePort }
func (s *ftpAnonScript) Match(target ScriptTarget) bool {
	svc := strings.ToLower(target.Service)
	return svc == "ftp" || target.Port == 21
}

func (s *ftpAnonScript) Run(ctx context.Context, target ScriptTarget) (*ScriptOutput, error) {
	timeout := 5 * time.Second
	addr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	reader.ReadString('\n') // banner

	fmt.Fprintf(conn, "USER anonymous\r\n")
	resp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(resp, "331") && !strings.HasPrefix(resp, "230") {
		return nil, nil // not accepted
	}

	fmt.Fprintf(conn, "PASS gomap@\r\n")
	resp, _ = reader.ReadString('\n')
	fmt.Fprintf(conn, "QUIT\r\n")

	if strings.HasPrefix(resp, "230") {
		return &ScriptOutput{
			ScriptID: s.ID(),
			Output:   "Anonymous FTP login allowed",
			Elements: map[string]string{"allowed": "true"},
		}, nil
	}

	return nil, nil
}

// mysqlInfoScript retrieves MySQL server greeting info.
type mysqlInfoScript struct{}

func (s *mysqlInfoScript) ID() string          { return "mysql-info" }
func (s *mysqlInfoScript) Description() string { return "Retrieves MySQL server version and capabilities" }
func (s *mysqlInfoScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDefault, CategoryDiscovery, CategorySafe}
}
func (s *mysqlInfoScript) Phase() ScriptPhase { return PhasePort }
func (s *mysqlInfoScript) Match(target ScriptTarget) bool {
	svc := strings.ToLower(target.Service)
	return svc == "mysql" || target.Port == 3306
}

func (s *mysqlInfoScript) Run(ctx context.Context, target ScriptTarget) (*ScriptOutput, error) {
	timeout := 5 * time.Second
	addr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return nil, err
	}

	// MySQL greeting packet: 3 bytes length, 1 byte seq, 1 byte proto version,
	// then null-terminated version string
	payload := buf[4:n]
	if len(payload) < 2 {
		return nil, nil
	}

	protoVersion := payload[0]
	versionEnd := 1
	for versionEnd < len(payload) && payload[versionEnd] != 0 {
		versionEnd++
	}
	version := string(payload[1:versionEnd])

	return &ScriptOutput{
		ScriptID: s.ID(),
		Output:   fmt.Sprintf("MySQL %s (protocol %d)", version, protoVersion),
		Elements: map[string]string{
			"version":         version,
			"protocolVersion": fmt.Sprintf("%d", protoVersion),
		},
	}, nil
}

// redisInfoScript retrieves Redis server info.
type redisInfoScript struct{}

func (s *redisInfoScript) ID() string          { return "redis-info" }
func (s *redisInfoScript) Description() string { return "Retrieves Redis server version and info" }
func (s *redisInfoScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDefault, CategoryDiscovery, CategorySafe}
}
func (s *redisInfoScript) Phase() ScriptPhase { return PhasePort }
func (s *redisInfoScript) Match(target ScriptTarget) bool {
	svc := strings.ToLower(target.Service)
	return svc == "redis" || target.Port == 6379
}

func (s *redisInfoScript) Run(ctx context.Context, target ScriptTarget) (*ScriptOutput, error) {
	timeout := 5 * time.Second
	addr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	fmt.Fprintf(conn, "*1\r\n$4\r\nINFO\r\n")

	reader := bufio.NewReader(conn)
	firstLine, _ := reader.ReadString('\n')

	if strings.HasPrefix(firstLine, "-") {
		// Auth required or error
		return &ScriptOutput{
			ScriptID: s.ID(),
			Output:   "Authentication required",
			Elements: map[string]string{"auth": "required"},
		}, nil
	}

	// Read bulk string response
	var sb strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		sb.WriteString(line)
		sb.WriteString("\n")
		// Stop after server section
		if strings.HasPrefix(line, "# Clients") {
			break
		}
	}

	info := sb.String()
	elements := make(map[string]string)

	for _, line := range strings.Split(info, "\n") {
		if idx := strings.Index(line, ":"); idx > 0 {
			key := line[:idx]
			val := line[idx+1:]
			switch key {
			case "redis_version", "os", "tcp_port", "uptime_in_days", "connected_clients":
				elements[key] = val
			}
		}
	}

	version := elements["redis_version"]
	if version == "" {
		version = "unknown"
	}

	return &ScriptOutput{
		ScriptID: s.ID(),
		Output:   fmt.Sprintf("Redis %s", version),
		Elements: elements,
	}, nil
}

// httpHeadersScript retrieves HTTP response headers.
type httpHeadersScript struct{}

func (s *httpHeadersScript) ID() string          { return "http-headers" }
func (s *httpHeadersScript) Description() string { return "Retrieves HTTP response headers" }
func (s *httpHeadersScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategorySafe}
}
func (s *httpHeadersScript) Phase() ScriptPhase { return PhasePort }
func (s *httpHeadersScript) Match(target ScriptTarget) bool {
	svc := strings.ToLower(target.Service)
	return svc == "http" || svc == "https" || svc == "http-proxy" ||
		target.Port == 80 || target.Port == 443 || target.Port == 8080 || target.Port == 8443
}

func (s *httpHeadersScript) Run(ctx context.Context, target ScriptTarget) (*ScriptOutput, error) {
	timeout := 5 * time.Second
	addr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target.Host)
	conn.Write([]byte(req))

	reader := bufio.NewReader(conn)
	elements := make(map[string]string)

	// Read and skip status line
	reader.ReadString('\n')

	// Read headers
	var headers []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		headers = append(headers, line)
		if idx := strings.Index(line, ": "); idx > 0 {
			key := strings.ToLower(line[:idx])
			val := line[idx+2:]
			elements[key] = val
		}
	}

	if len(headers) == 0 {
		return nil, nil
	}

	return &ScriptOutput{
		ScriptID: s.ID(),
		Output:   strings.Join(headers, "\n  "),
		Elements: elements,
	}, nil
}

// httpRobotsScript retrieves robots.txt.
type httpRobotsScript struct{}

func (s *httpRobotsScript) ID() string          { return "http-robots" }
func (s *httpRobotsScript) Description() string { return "Retrieves and parses robots.txt disallowed entries" }
func (s *httpRobotsScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategorySafe}
}
func (s *httpRobotsScript) Phase() ScriptPhase { return PhasePort }
func (s *httpRobotsScript) Match(target ScriptTarget) bool {
	svc := strings.ToLower(target.Service)
	return svc == "http" || svc == "https" || target.Port == 80 || target.Port == 443 || target.Port == 8080
}

func (s *httpRobotsScript) Run(ctx context.Context, target ScriptTarget) (*ScriptOutput, error) {
	timeout := 5 * time.Second
	addr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("GET /robots.txt HTTP/1.0\r\nHost: %s\r\n\r\n", target.Host)
	conn.Write([]byte(req))

	reader := bufio.NewReader(conn)

	// Read status line
	status, _ := reader.ReadString('\n')
	if !strings.Contains(status, "200") {
		return nil, nil // no robots.txt
	}

	// Skip headers
	for {
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}

	// Parse disallowed paths
	var disallowed []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path := strings.TrimSpace(line[9:])
			if path != "" {
				disallowed = append(disallowed, path)
			}
		}
	}

	if len(disallowed) == 0 {
		return nil, nil
	}

	return &ScriptOutput{
		ScriptID: s.ID(),
		Output:   fmt.Sprintf("%d disallowed entries: %s", len(disallowed), strings.Join(disallowed, ", ")),
		Elements: map[string]string{
			"count":   fmt.Sprintf("%d", len(disallowed)),
			"entries": strings.Join(disallowed, ", "),
		},
	}, nil
}

// bannerScript is a generic banner grabber for any open port.
type bannerScript struct{}

func (s *bannerScript) ID() string          { return "banner" }
func (s *bannerScript) Description() string { return "Grabs the service banner from any open port" }
func (s *bannerScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategorySafe}
}
func (s *bannerScript) Phase() ScriptPhase { return PhasePort }
func (s *bannerScript) Match(target ScriptTarget) bool {
	return true // matches any open port
}

func (s *bannerScript) Run(ctx context.Context, target ScriptTarget) (*ScriptOutput, error) {
	timeout := 3 * time.Second
	addr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n == 0 {
		return nil, nil
	}

	banner := strings.TrimSpace(string(buf[:n]))
	if banner == "" {
		return nil, nil
	}

	// Truncate long banners
	if len(banner) > 256 {
		banner = banner[:256] + "..."
	}

	return &ScriptOutput{
		ScriptID: s.ID(),
		Output:   banner,
	}, nil
}
