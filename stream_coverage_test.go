package gomap

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestScanCIDRStreamInvalidCIDR(t *testing.T) {
	ctx := context.Background()
	ch := ScanCIDRStream(ctx, "not-valid", ScanOptions{
		Ports:   []int{80},
		Timeout: 1 * time.Second,
	})

	var gotError bool
	for ev := range ch {
		if ev.Error != nil {
			gotError = true
		}
	}
	if !gotError {
		t.Error("expected error event for invalid CIDR")
	}
}

func TestScanCIDRStreamSmallRange(t *testing.T) {
	// Start a listener on 127.0.0.1
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch := ScanCIDRStream(ctx, "127.0.0.0/30", ScanOptions{
		Ports:   []int{port},
		Timeout: 1 * time.Second,
		Workers: 2,
	})

	var doneCount int
	for ev := range ch {
		if ev.Done {
			doneCount++
		}
	}
	// /30 has 2 usable hosts
	if doneCount < 1 {
		t.Errorf("expected at least 1 done event, got %d", doneCount)
	}
}

func TestScanCIDRStreamWithExcludes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch := ScanCIDRStream(ctx, "127.0.0.0/30", ScanOptions{
		Ports:        []int{1},
		Timeout:      500 * time.Millisecond,
		Workers:      1,
		ExcludeHosts: []string{"127.0.0.1"},
	})

	var hosts []string
	for ev := range ch {
		if ev.Done && ev.Host != "" {
			hosts = append(hosts, ev.Host)
		}
	}

	for _, h := range hosts {
		if h == "127.0.0.1" {
			t.Error("127.0.0.1 should have been excluded")
		}
	}
}

func TestScanCIDRStreamHostTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch := ScanCIDRStream(ctx, "127.0.0.0/30", ScanOptions{
		Ports:       []int{1},
		Timeout:     200 * time.Millisecond,
		HostTimeout: 1 * time.Second,
		Workers:     1,
	})

	for range ch {
	}
	// Main check: it doesn't hang
}

func TestScanHostStreamOpenPortResult(t *testing.T) {
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

	ch := ScanHostStream(ctx, "127.0.0.1", ScanOptions{
		Ports:   []int{port},
		Timeout: 2 * time.Second,
		Workers: 1,
	})

	var foundOpen, foundDone bool
	for ev := range ch {
		if ev.Port != nil && ev.Port.Open {
			foundOpen = true
		}
		if ev.Done {
			foundDone = true
		}
	}
	if !foundOpen {
		t.Error("expected open port event")
	}
	if !foundDone {
		t.Error("expected done event")
	}
}

func TestResolvePortListFastScan(t *testing.T) {
	opts := ScanOptions{FastScan: true}
	opts.defaults()
	pl := resolvePortList(opts)
	if len(pl) == 0 {
		t.Error("fast scan should have ports")
	}
	if len(pl) != len(CommonPorts) {
		t.Errorf("fast scan ports = %d, want %d", len(pl), len(CommonPorts))
	}
}

func TestResolvePortListDefault(t *testing.T) {
	opts := ScanOptions{}
	opts.defaults()
	pl := resolvePortList(opts)
	if len(pl) == 0 {
		t.Error("default scan should have ports")
	}
	if len(pl) != len(DetailedPorts) {
		t.Errorf("default ports = %d, want %d", len(pl), len(DetailedPorts))
	}
}

func TestScanHostStreamOpenOnly(t *testing.T) {
	// Start listener on one port
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

	openPort := ln.Addr().(*net.TCPAddr).Port

	// Get a closed port
	closedLn, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	closedLn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch := ScanHostStream(ctx, "127.0.0.1", ScanOptions{
		Ports:    []int{openPort, closedPort},
		Timeout:  2 * time.Second,
		Workers:  2,
		OpenOnly: true,
	})

	var portEvents int
	for ev := range ch {
		if ev.Port != nil {
			portEvents++
			if !ev.Port.Open {
				t.Error("OpenOnly should filter closed ports")
			}
		}
	}
	if portEvents != 1 {
		t.Errorf("expected 1 open port event, got %d", portEvents)
	}
}
