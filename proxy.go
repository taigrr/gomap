package gomap

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// scanPortProxy performs a connect scan through HTTP CONNECT or SOCKS4 proxies.
func scanPortProxy(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, timeout time.Duration, proxies []string, tr *tracer) {
	result := PortResult{Port: port, Service: service}

	target := net.JoinHostPort(hostname, strconv.Itoa(port))

	for _, proxyURL := range proxies {
		if ctx.Err() != nil {
			break
		}

		conn, err := dialProxy(ctx, proxyURL, target, timeout)
		if err != nil {
			continue
		}
		conn.Close()

		tr.traceConnect(PacketReceived, "TCP", hostname, port, fmt.Sprintf("Connected via %s", proxyURL))
		result.Open = true
		result.State = PortOpen
		result.Reason = "syn-ack"
		resultCh <- result
		return
	}

	// All proxies failed
	result.State = PortFiltered
	result.Reason = "no-response"
	resultCh <- result
}

func dialProxy(ctx context.Context, proxyURL, target string, timeout time.Duration) (net.Conn, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "http", "https":
		return dialHTTPProxy(ctx, u, target, timeout)
	case "socks4":
		return dialSOCKS4Proxy(ctx, u, target, timeout)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}
}

func dialHTTPProxy(ctx context.Context, u *url.URL, target string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	proxyAddr := u.Host
	if !strings.Contains(proxyAddr, ":") {
		proxyAddr += ":8080"
	}

	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}

	conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if u.User != nil {
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", u.User.String())
	}
	req += "\r\n"

	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, err
	}

	// Read response (look for "200")
	buf := make([]byte, readBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, err
	}

	resp := string(buf[:n])
	if !strings.Contains(resp, "200") {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(strings.SplitN(resp, "\r\n", 2)[0]))
	}

	conn.SetDeadline(time.Time{}) // clear deadline
	return conn, nil
}

func dialSOCKS4Proxy(ctx context.Context, u *url.URL, target string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	proxyAddr := u.Host
	if !strings.Contains(proxyAddr, ":") {
		proxyAddr += ":1080"
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	// Resolve target IP (SOCKS4 requires IP, not hostname)
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolving %s: %w", host, err)
	}
	ip4 := ips[0].To4()
	if ip4 == nil {
		return nil, fmt.Errorf("SOCKS4 requires IPv4 target")
	}

	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}

	conn.SetDeadline(time.Now().Add(timeout))

	// SOCKS4 CONNECT request
	req := []byte{
		0x04,                        // version
		0x01,                        // CONNECT
		byte(port >> 8), byte(port), // port big-endian
		ip4[0], ip4[1], ip4[2], ip4[3], // IP
		0x00, // userid (empty)
	}

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Read 8-byte response
	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}

	if resp[1] != 0x5A {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 request rejected (code 0x%02x)", resp[1])
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}
