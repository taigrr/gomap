package gomap

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestGrabBannerSSH(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	ctx := context.Background()

	sv, err := GrabBanner(ctx, "127.0.0.1", port, 2*time.Second, nil)
	if err != nil {
		t.Fatalf("GrabBanner error: %v", err)
	}

	if sv.Service != "ssh" {
		t.Errorf("service = %q, want ssh", sv.Service)
	}
	if sv.Banner == "" {
		t.Error("banner should not be empty for SSH")
	}
}

func TestGrabBannerHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	ctx := context.Background()

	sv, err := GrabBanner(ctx, "127.0.0.1", port, 2*time.Second, nil)
	if err != nil {
		t.Fatalf("GrabBanner error: %v", err)
	}
	_ = sv
}

func TestGrabBannerFTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("220 FTP Server Ready\r\n"))
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	ctx := context.Background()

	sv, err := GrabBanner(ctx, "127.0.0.1", port, 2*time.Second, nil)
	if err != nil {
		t.Fatalf("GrabBanner error: %v", err)
	}

	if sv.Service != "ftp" {
		t.Errorf("service = %q, want ftp", sv.Service)
	}
}

func TestGrabBannerSMTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("220 mail.example.com SMTP ready\r\n"))
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	ctx := context.Background()

	sv, err := GrabBanner(ctx, "127.0.0.1", port, 2*time.Second, nil)
	if err != nil {
		t.Fatalf("GrabBanner error: %v", err)
	}

	if sv.Service != "smtp" {
		t.Errorf("service = %q, want smtp", sv.Service)
	}
}

func TestGrabBannerContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := GrabBanner(ctx, "192.0.2.1", 80, 100*time.Millisecond, nil)
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

func TestGrabBanners(t *testing.T) {
	ln1, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln1.Close()
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln2.Close()

	go func() {
		for {
			conn, err := ln1.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("SSH-2.0-OpenSSH_8.0\r\n"))
			conn.Close()
		}
	}()
	go func() {
		for {
			conn, err := ln2.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("220 FTP Ready\r\n"))
			conn.Close()
		}
	}()

	port1 := ln1.Addr().(*net.TCPAddr).Port
	port2 := ln2.Addr().(*net.TCPAddr).Port

	result := &ScanResult{
		Ports: []PortResult{
			{Port: port1, Open: true, State: PortOpen},
			{Port: port2, Open: true, State: PortOpen},
			{Port: 1, Open: false, State: PortClosed},
		},
	}

	ctx := context.Background()
	opts := ScanOptions{Timeout: 2 * time.Second}
	versions := GrabBanners(ctx, "127.0.0.1", result, opts)

	if len(versions) < 2 {
		t.Errorf("expected at least 2 versions, got %d", len(versions))
	}
}

func TestIdentifyServiceSimple(t *testing.T) {
	tests := []struct {
		port   int
		banner string
		want   string
	}{
		{22, "SSH-2.0-OpenSSH_9.0", "ssh"},
		{21, "220 FTP Server Ready", "ftp"},
		{25, "220 mail.example.com SMTP", "smtp"},
		{0, "HTTP/1.1 200 OK", "http"},
		{0, "+OK POP3 server ready", "pop3"},
		{0, "* OK IMAP ready", "imap"},
		{0, "+PONG", "redis"},
	}
	for _, tt := range tests {
		got := identifyServiceSimple(tt.port, tt.banner)
		if got != tt.want {
			t.Errorf("identifyServiceSimple(%d, %q) = %q, want %q", tt.port, tt.banner, got, tt.want)
		}
	}
}

func TestExtractVersionSimple(t *testing.T) {
	tests := []struct {
		banner string
		want   string
	}{
		{"SSH-2.0-OpenSSH_9.0", "OpenSSH_9.0"},
		{"HTTP/1.1 200 OK", "HTTP/1.1 200 OK"},
		{"", ""},
		{"random banner", ""},
	}
	for _, tt := range tests {
		got := extractVersionSimple(tt.banner)
		if got != tt.want {
			t.Errorf("extractVersionSimple(%q) = %q, want %q", tt.banner, got, tt.want)
		}
	}
}

func TestDefaultProbeDB(t *testing.T) {
	db, err := DefaultProbeDB()
	if err != nil {
		t.Fatalf("DefaultProbeDB error: %v", err)
	}
	if db == nil {
		t.Fatal("DefaultProbeDB returned nil")
	}
	if len(db.Probes) == 0 {
		t.Error("expected probes in embedded database")
	}
	t.Logf("Embedded probe DB: %d probes", len(db.Probes))

	// Check NULL probe exists
	found := false
	for _, p := range db.Probes {
		if p.Name == "NULL" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected NULL probe in database")
	}
}

func TestLoadProbeDBFromFile(t *testing.T) {
	// Test that ProbeFile option works (file doesn't exist, should error)
	_, err := loadProbeDB("/nonexistent/nmap-service-probes")
	if err == nil {
		t.Error("expected error loading nonexistent probe file")
	}
}

func init() {
	_ = fmt.Sprint
}
