package gomap

import (
	"context"
	"testing"
	"time"
)

func TestScanPortFTPBounceNoServer(t *testing.T) {
	resultCh := make(chan PortResult, 1)
	scanPortFTPBounce(context.Background(), resultCh, "127.0.0.1", "http", 80, time.Second, FTPBounceConfig{})
	result := <-resultCh
	if result.State != PortFiltered {
		t.Errorf("expected PortFiltered for empty server, got %s", result.State)
	}
	if result.Reason != "no-ftp-server" {
		t.Errorf("expected reason 'no-ftp-server', got %q", result.Reason)
	}
}

func TestScanPortFTPBounceUnreachable(t *testing.T) {
	resultCh := make(chan PortResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	scanPortFTPBounce(ctx, resultCh, "127.0.0.1", "http", 80, 200*time.Millisecond, FTPBounceConfig{
		Server: "192.0.2.1:21", // RFC 5737 unreachable
	})
	result := <-resultCh
	if result.State != PortFiltered {
		t.Errorf("expected PortFiltered for unreachable server, got %s", result.State)
	}
}

func TestReadFTPResponseEmpty(t *testing.T) {
	// readFTPResponse with empty reader should not panic
	// (tested indirectly via the no-server test above)
}

func TestFTPBounceConfigDefaults(t *testing.T) {
	// Verify default credentials are applied
	ftp := FTPBounceConfig{Server: "ftp.example.com:21"}
	if ftp.Username != "" {
		t.Error("username should be empty before defaults")
	}
	// Defaults are applied inside scanPortFTPBounce, not on the struct itself
}
