package gomap

import (
	"testing"
	"time"
)

func TestRateLimiterMaxRate(t *testing.T) {
	rl := NewRateLimiter(0, 100) // 100 pps = 10ms interval
	if rl.interval != 10*time.Millisecond {
		t.Errorf("interval = %v, want 10ms", rl.interval)
	}

	start := time.Now()
	for i := 0; i < 5; i++ {
		rl.Wait()
	}
	elapsed := time.Since(start)

	// Should take at least 40ms (5 waits - first is free, 4 * 10ms)
	if elapsed < 35*time.Millisecond {
		t.Errorf("5 waits took %v, expected >= 40ms", elapsed)
	}
}

func TestRateLimiterNoLimit(t *testing.T) {
	rl := NewRateLimiter(0, 0)
	start := time.Now()
	for i := 0; i < 100; i++ {
		rl.Wait()
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Error("unlimited rate limiter should not block")
	}
}

func TestRateLimiterNil(t *testing.T) {
	var rl *RateLimiter
	rl.Wait() // should not panic
}

func TestRateLimiterMinWorkers(t *testing.T) {
	rl := NewRateLimiter(1000, 0) // 1000 pps
	w := rl.MinWorkers(3 * time.Second)
	if w != 3000 {
		t.Errorf("MinWorkers = %d, want 3000", w)
	}
}

func TestRateLimiterMinWorkersZero(t *testing.T) {
	rl := NewRateLimiter(0, 0)
	if rl.MinWorkers(time.Second) != 0 {
		t.Error("MinWorkers should be 0 with no min rate")
	}
}
