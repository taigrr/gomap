package gomap

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// mockFTPServer starts a minimal FTP server that supports the bounce scan protocol.
// It responds to USER, PASS, PORT, and LIST commands.
func mockFTPServer(t *testing.T, portOpen bool) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start mock FTP server: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleFTPClient(conn, portOpen)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

func handleFTPClient(conn net.Conn, portOpen bool) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send banner
	fmt.Fprintf(conn, "220 Mock FTP Server ready\r\n")

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		cmd := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(cmd, "USER"):
			fmt.Fprintf(conn, "331 Please specify the password.\r\n")
		case strings.HasPrefix(cmd, "PASS"):
			fmt.Fprintf(conn, "230 Login successful.\r\n")
		case strings.HasPrefix(cmd, "PORT"):
			fmt.Fprintf(conn, "200 PORT command successful.\r\n")
		case strings.HasPrefix(cmd, "LIST"):
			if portOpen {
				fmt.Fprintf(conn, "150 Opening data connection.\r\n")
				fmt.Fprintf(conn, "226 Transfer complete.\r\n")
			} else {
				fmt.Fprintf(conn, "425 Can't open data connection.\r\n")
			}
		case strings.HasPrefix(cmd, "QUIT"):
			fmt.Fprintf(conn, "221 Goodbye.\r\n")
			return
		}
	}
}

func TestScanPortFTPBounceOpen(t *testing.T) {
	addr, cleanup := mockFTPServer(t, true)
	defer cleanup()

	resultCh := make(chan PortResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	scanPortFTPBounce(ctx, resultCh, "127.0.0.1", "http", 80, 2*time.Second, FTPBounceConfig{
		Server: addr,
	})
	result := <-resultCh
	if result.State != PortOpen {
		t.Errorf("expected PortOpen, got %s (reason: %s)", result.State, result.Reason)
	}
	if result.Reason != "ftp-bounce" {
		t.Errorf("expected reason 'ftp-bounce', got %q", result.Reason)
	}
}

func TestScanPortFTPBounceClosed(t *testing.T) {
	addr, cleanup := mockFTPServer(t, false)
	defer cleanup()

	resultCh := make(chan PortResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	scanPortFTPBounce(ctx, resultCh, "127.0.0.1", "http", 80, 2*time.Second, FTPBounceConfig{
		Server: addr,
	})
	result := <-resultCh
	if result.State != PortClosed {
		t.Errorf("expected PortClosed, got %s (reason: %s)", result.State, result.Reason)
	}
}

func TestScanPortFTPBounceDefaultCredentials(t *testing.T) {
	addr, cleanup := mockFTPServer(t, true)
	defer cleanup()

	resultCh := make(chan PortResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Empty username/password should default to anonymous/gomap@
	scanPortFTPBounce(ctx, resultCh, "127.0.0.1", "ssh", 22, 2*time.Second, FTPBounceConfig{
		Server: addr,
	})
	result := <-resultCh
	// Should still work with defaults
	if result.State != PortOpen {
		t.Errorf("expected PortOpen with default creds, got %s", result.State)
	}
}

func TestReadFTPResponse(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("220 Hello\r\n"))
	resp, err := readFTPResponse(reader)
	if err != nil {
		t.Fatal(err)
	}
	if resp != "220 Hello" {
		t.Errorf("expected '220 Hello', got %q", resp)
	}
}

func TestReadFTPResponseEmptyInput(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(""))
	_, err := readFTPResponse(reader)
	if err == nil {
		t.Error("expected error on empty input")
	}
}

// mockFTPServerLoginFail starts an FTP server that rejects login.
func mockFTPServerLoginFail(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start mock FTP server: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				fmt.Fprintf(c, "220 Mock FTP\r\n")
				reader := bufio.NewReader(c)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.ToUpper(strings.TrimSpace(line))
					switch {
					case strings.HasPrefix(cmd, "USER"):
						fmt.Fprintf(c, "331 Password required\r\n")
					case strings.HasPrefix(cmd, "PASS"):
						fmt.Fprintf(c, "530 Login incorrect.\r\n")
						return
					}
				}
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

func TestScanPortFTPBounceLoginFail(t *testing.T) {
	addr, cleanup := mockFTPServerLoginFail(t)
	defer cleanup()

	resultCh := make(chan PortResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	scanPortFTPBounce(ctx, resultCh, "127.0.0.1", "http", 80, 2*time.Second, FTPBounceConfig{
		Server: addr,
	})
	result := <-resultCh
	if result.State != PortFiltered {
		t.Errorf("expected PortFiltered on login failure, got %s", result.State)
	}
	if result.Reason != "ftp-login-failed" {
		t.Errorf("expected reason 'ftp-login-failed', got %q", result.Reason)
	}
}
