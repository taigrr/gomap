package gomap

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ResumeState contains the state needed to resume an interrupted scan.
type ResumeState struct {
	// Version identifies the resume file format.
	Version int `json:"version"`

	// StartTime is when the original scan began.
	StartTime time.Time `json:"startTime"`

	// Targets is the full list of targets.
	Targets []string `json:"targets"`

	// CompletedHosts tracks which hosts have been fully scanned.
	CompletedHosts map[string]bool `json:"completedHosts"`

	// Options stores the scan configuration.
	Options ResumeOptions `json:"options"`
}

// ResumeOptions is a serializable subset of ScanOptions.
type ResumeOptions struct {
	ScanType  string `json:"scanType"`
	FastScan  bool   `json:"fastScan"`
	TopPorts  int    `json:"topPorts,omitempty"`
	PortSpec  string `json:"portSpec,omitempty"`
	Timing    string `json:"timing,omitempty"`
}

// SaveResume writes the resume state to a file.
func SaveResume(path string, state *ResumeState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling resume state: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// LoadResume reads a resume state from a file.
func LoadResume(path string) (*ResumeState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading resume file: %w", err)
	}
	var state ResumeState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing resume file: %w", err)
	}
	if state.Version != 1 {
		return nil, fmt.Errorf("unsupported resume file version: %d", state.Version)
	}
	return &state, nil
}

// RemainingTargets returns targets not yet completed.
func (s *ResumeState) RemainingTargets() []string {
	var remaining []string
	for _, t := range s.Targets {
		if !s.CompletedHosts[t] {
			remaining = append(remaining, t)
		}
	}
	return remaining
}

// MarkComplete marks a host as completed and saves state.
func (s *ResumeState) MarkComplete(host, resumeFile string) {
	if s.CompletedHosts == nil {
		s.CompletedHosts = make(map[string]bool)
	}
	s.CompletedHosts[host] = true
	if resumeFile != "" {
		SaveResume(resumeFile, s)
	}
}
