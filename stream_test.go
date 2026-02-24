package gomap

import (
	"context"
	"testing"
	"time"
)

func TestScanHostStreamCancelation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	ch := ScanHostStream(ctx, "scanme.nmap.org", ScanOptions{
		Ports:   []int{80},
		Timeout: 1 * time.Second,
	})

	// Should drain quickly without blocking
	var events []ScanEvent
	for ev := range ch {
		events = append(events, ev)
	}

	// Should get at least a done or error event
	if len(events) == 0 {
		t.Error("expected at least one event from cancelled scan")
	}
}

func TestScanHostStreamLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch := ScanHostStream(ctx, "127.0.0.1", ScanOptions{
		Ports:   []int{1}, // likely closed
		Timeout: 1 * time.Second,
	})

	var gotDone bool
	for ev := range ch {
		if ev.Done {
			gotDone = true
		}
	}

	if !gotDone {
		t.Error("expected Done event")
	}
}

func TestResolvePortList(t *testing.T) {
	opts := ScanOptions{
		Ports:        []int{22, 80, 443, 8080},
		ExcludePorts: []int{80, 443},
	}
	pl := resolvePortList(opts)
	if _, ok := pl[80]; ok {
		t.Error("port 80 should be excluded")
	}
	if _, ok := pl[22]; !ok {
		t.Error("port 22 should be present")
	}
}

func TestSleepCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	<-sleepCtx(ctx, 10*time.Second)
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Errorf("sleepCtx should return quickly on cancel, took %v", elapsed)
	}
}
