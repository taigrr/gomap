package gomap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
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

func TestDialHTTPProxyDecodedCredentials(t *testing.T) {
	for _, tc := range []struct {
		name, username, password string
		noPassword               bool
	}{
		{name: "reserved characters", username: "user@example.com", password: "p@ss:%/ word"},
		{name: "unicode", username: "utilisateur", password: "café"},
		{name: "empty password", username: "user"},
		{name: "username only", username: "user", noPassword: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			authCh := make(chan string, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					authCh <- "accept failed"
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					authCh <- "read failed"
					return
				}
				authCh <- request.Header.Get("Proxy-Authorization")
				io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
			}()
			proxyURL := &url.URL{Scheme: "http", Host: listener.Addr().String(), User: url.UserPassword(tc.username, tc.password)}
			if tc.noPassword {
				proxyURL.User = url.User(tc.username)
			}
			conn, err := dialProxy(context.Background(), proxyURL.String(), "example.com:443", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			expected := &http.Request{Header: make(http.Header)}
			expected.SetBasicAuth(tc.username, tc.password)
			if got, want := <-authCh, expected.Header.Get("Authorization"); got != want {
				t.Fatalf("Proxy-Authorization = %q, want %q", got, want)
			}
		})
	}
}

func TestDialHTTPProxyResponseParsing(t *testing.T) {
	for _, tc := range []struct {
		name      string
		fragments []string
		wantError bool
		payload   string
	}{
		{"buffered tunnel data", []string{"HTTP/1.1 200 OK\r\n\r\nSSH-2.0-test\r\n"}, false, "SSH-2.0-test\r\n"},
		{"fragmented success", []string{"HTTP/1.1 2", "00 Connection established\r\nX-Proxy: ok\r\n\r\n"}, false, ""},
		{"status in header", []string{"HTTP/1.1 407 Authentication Required\r\nX-Code: 200\r\n\r\n"}, true, ""},
		{"status in reason", []string{"HTTP/1.1 500 Error 200\r\n\r\n"}, true, ""},
		{"truncated headers", []string{"HTTP/1.1 200 OK\r\n"}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					return
				}
				if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
					return
				}
				for _, fragment := range tc.fragments {
					if _, err := io.WriteString(conn, fragment); err != nil {
						return
					}
					if len(tc.fragments) > 1 {
						time.Sleep(20 * time.Millisecond)
					}
				}
			}()
			conn, err := dialHTTPProxy(context.Background(), mustParseURL(t, "http://"+listener.Addr().String()), "example.com:443", time.Second)
			if conn != nil {
				if tc.payload != "" {
					data, readErr := io.ReadAll(conn)
					if readErr != nil || string(data) != tc.payload {
						t.Errorf("tunnel data = %q, error %v; want %q", data, readErr, tc.payload)
					}
				}
				_ = conn.Close()
			}
			<-done
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, want error %v", err, tc.wantError)
			}
		})
	}
}
