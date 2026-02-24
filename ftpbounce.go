package gomap

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// FTPBounceConfig holds the FTP relay server configuration.
type FTPBounceConfig struct {
	// Server is the FTP server host:port to use as relay.
	Server string
	// Username for FTP login (default "anonymous").
	Username string
	// Password for FTP login (default "gomap@").
	Password string
}

// scanPortFTPBounce uses an FTP server's PORT command to scan a port on the target.
func scanPortFTPBounce(ctx context.Context, resultCh chan<- PortResult, targetHost, service string, port int, timeout time.Duration, ftp FTPBounceConfig) {
	result := PortResult{Port: port, Service: service}

	if ftp.Server == "" {
		result.setStateReason(PortFiltered, "no-ftp-server")
		resultCh <- result
		return
	}
	if ftp.Username == "" {
		ftp.Username = "anonymous"
	}
	if ftp.Password == "" {
		ftp.Password = "gomap@"
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", ftp.Server)
	if err != nil {
		result.setStateReason(PortFiltered, "ftp-connect-error")
		resultCh <- result
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// Read banner
	if _, err := readFTPResponse(reader); err != nil {
		result.setStateReason(PortFiltered, "ftp-banner-error")
		resultCh <- result
		return
	}

	// Login
	fmt.Fprintf(conn, "USER %s\r\n", ftp.Username)
	resp, err := readFTPResponse(reader)
	if err != nil {
		result.setStateReason(PortFiltered, "ftp-read-error")
		resultCh <- result
		return
	}
	if strings.HasPrefix(resp, "331") {
		fmt.Fprintf(conn, "PASS %s\r\n", ftp.Password)
		resp, err = readFTPResponse(reader)
		if err != nil {
			result.setStateReason(PortFiltered, "ftp-read-error")
			resultCh <- result
			return
		}
	}
	if !strings.HasPrefix(resp, "230") {
		result.setStateReason(PortFiltered, "ftp-login-failed")
		resultCh <- result
		return
	}

	// Resolve target IP for PORT command
	targetIP := net.ParseIP(targetHost)
	if targetIP == nil {
		ips, err := net.LookupIP(targetHost)
		if err != nil || len(ips) == 0 {
			result.setStateReason(PortFiltered, "resolve-error")
			resultCh <- result
			return
		}
		targetIP = ips[0]
	}

	ip4 := targetIP.To4()
	if ip4 == nil {
		result.setStateReason(PortFiltered, "ipv4-only")
		resultCh <- result
		return
	}

	// Send PORT command: PORT h1,h2,h3,h4,p1,p2
	p1 := port / 256
	p2 := port % 256
	portCmd := fmt.Sprintf("PORT %d,%d,%d,%d,%d,%d\r\n", ip4[0], ip4[1], ip4[2], ip4[3], p1, p2)
	fmt.Fprint(conn, portCmd)
	resp, err = readFTPResponse(reader)
	if err != nil {
		result.setStateReason(PortFiltered, "ftp-read-error")
		resultCh <- result
		return
	}
	if !strings.HasPrefix(resp, "200") {
		result.setStateReason(PortFiltered, "port-rejected")
		resultCh <- result
		return
	}

	// LIST triggers the FTP server to connect to the target port
	fmt.Fprint(conn, "LIST\r\n")
	resp, _ = readFTPResponse(reader)

	// 150/226 = connection successful = port open
	// 425/426 = connection failed = port closed
	if strings.HasPrefix(resp, "150") || strings.HasPrefix(resp, "226") {
		result.setStateReason(PortOpen, "ftp-bounce")
		// Read the completion response (best-effort)
		if strings.HasPrefix(resp, "150") {
			readFTPResponse(reader) //nolint:errcheck // completion response is optional
		}
	} else {
		result.setStateReason(PortClosed, "ftp-bounce")
	}

	fmt.Fprint(conn, "QUIT\r\n")
	resultCh <- result
}

func readFTPResponse(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	return strings.TrimSpace(line), err
}
