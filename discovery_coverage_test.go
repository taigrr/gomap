package gomap

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestHostResultString(t *testing.T) {
	tests := []struct {
		name string
		hr   HostResult
		want []string // substrings that must appear
	}{
		{
			name: "alive with hostname",
			hr: HostResult{
				IP: "10.0.0.1", Hostname: "router.local",
				Alive: true, Method: DiscoveryConnect, Latency: 5 * time.Millisecond,
			},
			want: []string{"10.0.0.1", "router.local", "up", "connect"},
		},
		{
			name: "alive no hostname",
			hr: HostResult{
				IP: "10.0.0.2", Alive: true, Method: DiscoveryICMP, Latency: 1 * time.Millisecond,
			},
			want: []string{"10.0.0.2", "up", "icmp"},
		},
		{
			name: "down",
			hr:   HostResult{IP: "192.0.2.1"},
			want: []string{"192.0.2.1", "down"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.hr.String()
			for _, sub := range tt.want {
				if !contains(s, sub) {
					t.Errorf("HostResult.String() = %q, missing %q", s, sub)
				}
			}
		})
	}
}

func TestDiscoverHostsStream(t *testing.T) {
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
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch := DiscoverHostsStream(ctx, []string{"127.0.0.1"}, DiscoveryOptions{
		Methods: []DiscoveryMethod{DiscoveryConnect},
		Ports:   []int{port},
		Timeout: 2 * time.Second,
		Workers: 1,
	})

	var results []HostResult
	for r := range ch {
		results = append(results, r)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Alive {
		t.Error("localhost should be alive via stream")
	}
}

func TestDiscoverHostsStreamCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ch := DiscoverHostsStream(ctx, []string{"192.0.2.1", "192.0.2.2"}, DiscoveryOptions{
		Methods: []DiscoveryMethod{DiscoveryConnect},
		Ports:   []int{80},
		Timeout: 100 * time.Millisecond,
		Workers: 1,
	})

	// Should drain without blocking
	for range ch {
	}
}

func TestDiscoverCIDR(t *testing.T) {
	// Use a /30 on loopback — only 127.0.0.1 is local
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

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
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port

	results, err := DiscoverCIDR(ctx, "127.0.0.0/30", DiscoveryOptions{
		Methods: []DiscoveryMethod{DiscoveryConnect},
		Ports:   []int{port},
		Timeout: 1 * time.Second,
		Workers: 2,
	})
	if err != nil {
		t.Fatalf("DiscoverCIDR error: %v", err)
	}

	// /30 gives 2 usable hosts: 127.0.0.1 and 127.0.0.2
	if len(results) == 0 {
		t.Error("expected at least some results")
	}

	// At least 127.0.0.1 should be alive
	foundAlive := false
	for _, r := range results {
		if r.IP == "127.0.0.1" && r.Alive {
			foundAlive = true
		}
	}
	if !foundAlive {
		t.Error("expected 127.0.0.1 to be alive")
	}
}

func TestDiscoverCIDRInvalid(t *testing.T) {
	ctx := context.Background()
	_, err := DiscoverCIDR(ctx, "not-a-cidr", DiscoveryOptions{})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestIsConnectionRefused(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"generic error", net.UnknownNetworkError("fail"), false},
		{
			"OpError with connection refused string",
			&net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &net.OpError{
					Op:  "connect",
					Err: connectionRefusedError{},
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isConnectionRefused(tt.err); got != tt.want {
				t.Errorf("isConnectionRefused() = %v, want %v", got, tt.want)
			}
		})
	}

	// Test the string-based fallback
	err := connectionRefusedError{}
	if !isConnectionRefused(err) {
		t.Error("string fallback should match connection refused")
	}
}

// connectionRefusedError is a test helper that mimics a connection refused error.
type connectionRefusedError struct{}

func (connectionRefusedError) Error() string   { return "connect: connection refused" }
func (connectionRefusedError) Timeout() bool   { return false }
func (connectionRefusedError) Temporary() bool { return false }

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
