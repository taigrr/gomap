package gomap

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDialProxyUnsupportedScheme(t *testing.T) {
	_, err := dialProxy(context.TODO(), "ftp://proxy:21", "host:80", 0)
	if err == nil {
		t.Error("expected error for unsupported scheme")
	}
}

func TestDialHTTPProxySuccessWithBasicAuth(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	reqCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		n, readErr := conn.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}
		reqCh <- string(buf[:n])

		_, writeErr := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		errCh <- writeErr
	}()

	ctx := context.Background()
	conn, err := dialHTTPProxy(ctx, mustParseURL(t, fmt.Sprintf("http://user:pass@%s", listener.Addr().String())), "example.com:443", time.Second)
	if err != nil {
		t.Fatalf("dialHTTPProxy: %v", err)
	}
	conn.Close()

	request := <-reqCh
	if !strings.Contains(request, "CONNECT example.com:443 HTTP/1.1\r\n") {
		t.Fatalf("CONNECT line missing from request: %q", request)
	}
	if !strings.Contains(request, "Host: example.com:443\r\n") {
		t.Fatalf("Host header missing from request: %q", request)
	}
	if !strings.Contains(request, "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n") {
		t.Fatalf("basic auth header missing or malformed: %q", request)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("proxy server error: %v", err)
	}
}

func TestDialHTTPProxyRejectsNon200Response(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
	}()

	_, err = dialHTTPProxy(context.Background(), mustParseURL(t, fmt.Sprintf("http://%s", listener.Addr().String())), "example.com:443", time.Second)
	if err == nil {
		t.Fatal("expected error for non-200 proxy response")
	}
	if !strings.Contains(err.Error(), "407 Proxy Authentication Required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDialSOCKS4ProxySuccess(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	reqCh := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 9)
		_, _ = io.ReadFull(conn, buf)
		reqCh <- buf
		_, _ = conn.Write([]byte{0x00, 0x5A, 0x00, 0x50, 127, 0, 0, 1})
	}()

	conn, err := dialSOCKS4Proxy(context.Background(), mustParseURL(t, fmt.Sprintf("socks4://%s", listener.Addr().String())), "127.0.0.1:80", time.Second)
	if err != nil {
		t.Fatalf("dialSOCKS4Proxy: %v", err)
	}
	conn.Close()

	request := <-reqCh
	expected := []byte{0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 0x00}
	if string(request) != string(expected) {
		t.Fatalf("unexpected SOCKS4 request: got %v want %v", request, expected)
	}
}

func TestDialSOCKS4ProxyRejectsIPv6Target(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	_, err = dialSOCKS4Proxy(context.Background(), mustParseURL(t, fmt.Sprintf("socks4://%s", listener.Addr().String())), "[::1]:80", time.Second)
	if err == nil {
		t.Fatal("expected error for IPv6 SOCKS4 target")
	}
	if !strings.Contains(err.Error(), "SOCKS4 requires IPv4 target") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}

	return parsedURL
}
