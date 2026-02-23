package gomap

import (
	"fmt"
	"time"
)

// TimingTemplate represents nmap-compatible timing presets (T0-T5).
type TimingTemplate int

const (
	// TimingParanoid is T0: very slow, IDS evasion.
	// 5 min timeout, serial scan, 5 sec between probes.
	TimingParanoid TimingTemplate = iota

	// TimingSneaky is T1: slow, IDS evasion.
	// 15 sec timeout, serial scan, 1 sec between probes.
	TimingSneaky

	// TimingPolite is T2: conservative, reduces network load.
	// 10 sec timeout, serial scan, 400ms between probes.
	TimingPolite

	// TimingNormal is T3: default balanced timing.
	// 3 sec timeout, parallel scan.
	TimingNormal

	// TimingAggressive is T4: fast, assumes reliable network.
	// 1.25 sec timeout, high parallelism.
	TimingAggressive

	// TimingInsane is T5: maximum speed, may miss ports.
	// 300ms timeout, maximum parallelism.
	TimingInsane
)

// timingConfig holds the computed values for a timing template.
type timingConfig struct {
	Timeout     time.Duration
	Workers     int
	ProbeDelay  time.Duration
	MaxRetries  int
	HostTimeout time.Duration
}

// ApplyTiming configures ScanOptions based on a timing template.
func ApplyTiming(opts *ScanOptions, template TimingTemplate) {
	cfg := timingConfigs[template]
	opts.Timeout = cfg.Timeout
	if opts.Workers == 0 {
		opts.Workers = cfg.Workers
	}
}

// ApplyTimingDiscovery configures DiscoveryOptions based on a timing template.
func ApplyTimingDiscovery(opts *DiscoveryOptions, template TimingTemplate) {
	cfg := timingConfigs[template]
	opts.Timeout = cfg.Timeout
	if opts.Workers == 0 {
		opts.Workers = cfg.Workers
	}
}

var timingConfigs = map[TimingTemplate]timingConfig{
	TimingParanoid: {
		Timeout:     5 * time.Minute,
		Workers:     1,
		ProbeDelay:  5 * time.Second,
		MaxRetries:  10,
		HostTimeout: 0, // no limit
	},
	TimingSneaky: {
		Timeout:     15 * time.Second,
		Workers:     1,
		ProbeDelay:  1 * time.Second,
		MaxRetries:  10,
		HostTimeout: 0,
	},
	TimingPolite: {
		Timeout:     10 * time.Second,
		Workers:     1,
		ProbeDelay:  400 * time.Millisecond,
		MaxRetries:  10,
		HostTimeout: 0,
	},
	TimingNormal: {
		Timeout:     3 * time.Second,
		Workers:     500,
		ProbeDelay:  0,
		MaxRetries:  3,
		HostTimeout: 0,
	},
	TimingAggressive: {
		Timeout:     1250 * time.Millisecond,
		Workers:     1000,
		ProbeDelay:  0,
		MaxRetries:  2,
		HostTimeout: 5 * time.Minute,
	},
	TimingInsane: {
		Timeout:     300 * time.Millisecond,
		Workers:     2000,
		ProbeDelay:  0,
		MaxRetries:  1,
		HostTimeout: 75 * time.Second,
	},
}

// String returns the timing template name.
func (t TimingTemplate) String() string {
	switch t {
	case TimingParanoid:
		return "paranoid"
	case TimingSneaky:
		return "sneaky"
	case TimingPolite:
		return "polite"
	case TimingNormal:
		return "normal"
	case TimingAggressive:
		return "aggressive"
	case TimingInsane:
		return "insane"
	default:
		return "unknown"
	}
}

// ParseTimingTemplate converts a string (T0-T5 or name) to a TimingTemplate.
func ParseTimingTemplate(s string) (TimingTemplate, error) {
	switch s {
	case "0", "T0", "paranoid":
		return TimingParanoid, nil
	case "1", "T1", "sneaky":
		return TimingSneaky, nil
	case "2", "T2", "polite":
		return TimingPolite, nil
	case "3", "T3", "normal":
		return TimingNormal, nil
	case "4", "T4", "aggressive":
		return TimingAggressive, nil
	case "5", "T5", "insane":
		return TimingInsane, nil
	default:
		return TimingNormal, ErrInvalidTimingTemplate
	}
}

// ErrInvalidTimingTemplate is returned when an invalid timing template is specified.
var ErrInvalidTimingTemplate = fmt.Errorf("invalid timing template (valid: T0-T5, paranoid, sneaky, polite, normal, aggressive, insane)")
