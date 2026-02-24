package gomap

import (
	"context"
	"sync"
	"time"
)

// RateLimiter controls the packet sending rate.
// It uses a token bucket algorithm to enforce min/max rates.
type RateLimiter struct {
	mu       sync.Mutex
	minRate  int           // minimum packets per second (0 = no minimum)
	maxRate  int           // maximum packets per second (0 = no limit)
	interval time.Duration // minimum time between packets (derived from maxRate)
	last     time.Time     // last packet sent
}

// NewRateLimiter creates a rate limiter with the given constraints.
// minRate is the minimum packets/second (0 = no minimum).
// maxRate is the maximum packets/second (0 = unlimited).
func NewRateLimiter(minRate, maxRate int) *RateLimiter {
	rl := &RateLimiter{
		minRate: minRate,
		maxRate: maxRate,
	}
	if maxRate > 0 {
		rl.interval = time.Second / time.Duration(maxRate)
	}
	return rl
}

// Wait blocks until it's safe to send the next packet according to the rate limit.
// It returns immediately if the context is canceled.
func (rl *RateLimiter) Wait() {
	rl.WaitCtx(context.Background())
}

// WaitCtx blocks until it's safe to send the next packet, or ctx is canceled.
func (rl *RateLimiter) WaitCtx(ctx context.Context) {
	if rl == nil || rl.maxRate == 0 {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.last.IsZero() {
		rl.last = time.Now()
		return
	}

	elapsed := time.Since(rl.last)
	if elapsed < rl.interval {
		wait := rl.interval - elapsed
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	rl.last = time.Now()
}

// MinWorkers returns the minimum number of workers needed to sustain the minimum rate.
// Returns 0 if no minimum rate is set.
func (rl *RateLimiter) MinWorkers(timeoutPerProbe time.Duration) int {
	if rl == nil || rl.minRate == 0 {
		return 0
	}
	// workers needed = minRate * timeout_seconds
	needed := int(float64(rl.minRate) * timeoutPerProbe.Seconds())
	if needed < 1 {
		needed = 1
	}
	return needed
}
