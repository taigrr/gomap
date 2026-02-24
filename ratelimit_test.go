package gomap

import (
	"testing"
	"time"
)

func TestNewRateLimiter(t *testing.T) {
	rl := NewRateLimiter(0, 100)
	if rl.interval != 10*time.Millisecond {
		t.Errorf("expected 10ms interval for 100 pps, got %v", rl.interval)
	}

	rl2 := NewRateLimiter(0, 0)
	if rl2.interval != 0 {
		t.Errorf("expected 0 interval for unlimited, got %v", rl2.interval)
	}
}

func TestRateLimiterWait(t *testing.T) {
	rl := NewRateLimiter(0, 1000)
	start := time.Now()
	for i := 0; i < 10; i++ {
		rl.Wait()
	}
	elapsed := time.Since(start)
	// 10 packets at 1000 pps = ~9ms minimum (first is instant)
	if elapsed < 8*time.Millisecond {
		t.Errorf("rate limiter too fast: 10 packets in %v", elapsed)
	}
}

func TestRateLimiterWaitUnlimited(t *testing.T) {
	rl := NewRateLimiter(10, 0)
	start := time.Now()
	for i := 0; i < 100; i++ {
		rl.Wait()
	}
	elapsed := time.Since(start)
	// Unlimited should be nearly instant
	if elapsed > 10*time.Millisecond {
		t.Errorf("unlimited rate limiter too slow: %v", elapsed)
	}
}

func TestRateLimiterNil(t *testing.T) {
	var rl *RateLimiter
	// Should not panic
	rl.Wait()
}

func TestMinWorkers(t *testing.T) {
	tests := []struct {
		minRate int
		timeout time.Duration
		want    int
	}{
		{0, 3 * time.Second, 0},
		{100, 3 * time.Second, 300},
		{10, 1 * time.Second, 10},
		{1, 100 * time.Millisecond, 1},
	}
	for _, tt := range tests {
		rl := NewRateLimiter(tt.minRate, 0)
		got := rl.MinWorkers(tt.timeout)
		if got != tt.want {
			t.Errorf("MinWorkers(%d, %v) = %d, want %d", tt.minRate, tt.timeout, got, tt.want)
		}
	}
}
