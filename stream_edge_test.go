package gomap

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestScanCIDRStreamCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ch := ScanCIDRStream(ctx, "192.0.2.0/30", ScanOptions{
		Ports:   []int{80},
		Timeout: 100 * time.Millisecond,
	})

	// Should drain quickly without blocking
	for range ch {
	}
}

func TestScanHostStreamOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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

	var gotOpen, gotDone bool
	for ev := range ch {
		if ev.Port != nil && ev.Port.Open {
			gotOpen = true
		}
		if ev.Done {
			gotDone = true
		}
	}
	if !gotOpen {
		t.Error("expected open port event")
	}
	if !gotDone {
		t.Error("expected done event")
	}
}

func TestSleepCtxNormal(t *testing.T) {
	ctx := context.Background()
	start := time.Now()
	<-sleepCtx(ctx, 50*time.Millisecond)
	elapsed := time.Since(start)
	if elapsed < 40*time.Millisecond {
		t.Errorf("sleepCtx returned too early: %v", elapsed)
	}
}
