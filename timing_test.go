package gomap

import (
	"testing"
	"time"
)

func TestTimingTemplateString(t *testing.T) {
	tests := []struct {
		tt   TimingTemplate
		want string
	}{
		{TimingParanoid, "paranoid"},
		{TimingSneaky, "sneaky"},
		{TimingPolite, "polite"},
		{TimingNormal, "normal"},
		{TimingAggressive, "aggressive"},
		{TimingInsane, "insane"},
		{TimingTemplate(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.tt.String(); got != tt.want {
			t.Errorf("TimingTemplate(%d).String() = %q, want %q", tt.tt, got, tt.want)
		}
	}
}

func TestParseTimingTemplate(t *testing.T) {
	tests := []struct {
		input   string
		want    TimingTemplate
		wantErr bool
	}{
		{"T0", TimingParanoid, false},
		{"T1", TimingSneaky, false},
		{"T2", TimingPolite, false},
		{"T3", TimingNormal, false},
		{"T4", TimingAggressive, false},
		{"T5", TimingInsane, false},
		{"0", TimingParanoid, false},
		{"5", TimingInsane, false},
		{"paranoid", TimingParanoid, false},
		{"aggressive", TimingAggressive, false},
		{"insane", TimingInsane, false},
		{"invalid", TimingNormal, true},
	}
	for _, tt := range tests {
		got, err := ParseTimingTemplate(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseTimingTemplate(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("ParseTimingTemplate(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestApplyTiming(t *testing.T) {
	opts := ScanOptions{}
	ApplyTiming(&opts, TimingInsane)

	if opts.Timeout != 300*time.Millisecond {
		t.Errorf("insane timeout = %v, want 300ms", opts.Timeout)
	}
	if opts.Workers != 2000 {
		t.Errorf("insane workers = %d, want 2000", opts.Workers)
	}
}

func TestApplyTimingPreservesWorkers(t *testing.T) {
	opts := ScanOptions{Workers: 42}
	ApplyTiming(&opts, TimingInsane)

	// Should preserve user-set workers
	if opts.Workers != 42 {
		t.Errorf("workers = %d, want 42 (preserved)", opts.Workers)
	}
}

func TestApplyTimingDiscovery(t *testing.T) {
	opts := DiscoveryOptions{}
	ApplyTimingDiscovery(&opts, TimingParanoid)

	if opts.Timeout != 5*time.Minute {
		t.Errorf("paranoid timeout = %v, want 5m", opts.Timeout)
	}
	if opts.Workers != 1 {
		t.Errorf("paranoid workers = %d, want 1", opts.Workers)
	}
}

func TestAllTimingTemplatesHaveConfigs(t *testing.T) {
	templates := []TimingTemplate{
		TimingParanoid, TimingSneaky, TimingPolite,
		TimingNormal, TimingAggressive, TimingInsane,
	}
	for _, tt := range templates {
		cfg, ok := timingConfigs[tt]
		if !ok {
			t.Errorf("no config for timing template %s", tt)
			continue
		}
		if cfg.Timeout == 0 {
			t.Errorf("timing %s has zero timeout", tt)
		}
		if cfg.Workers == 0 {
			t.Errorf("timing %s has zero workers", tt)
		}
	}
}
