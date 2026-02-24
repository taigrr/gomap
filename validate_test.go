package gomap

import (
	"errors"
	"testing"
)

func TestScanOptionsValidateVersionIntensity(t *testing.T) {
	opts := ScanOptions{VersionIntensity: 10}
	err := opts.Validate()
	if !errors.Is(err, ErrInvalidScanOptions) {
		t.Errorf("expected ErrInvalidScanOptions for intensity=10, got %v", err)
	}

	opts = ScanOptions{VersionIntensity: -1}
	err = opts.Validate()
	if !errors.Is(err, ErrInvalidScanOptions) {
		t.Errorf("expected ErrInvalidScanOptions for intensity=-1, got %v", err)
	}
}

func TestScanOptionsValidateRateConflict(t *testing.T) {
	opts := ScanOptions{MinRate: 200, MaxRate: 100}
	err := opts.Validate()
	if !errors.Is(err, ErrInvalidScanOptions) {
		t.Errorf("expected ErrInvalidScanOptions for minRate > maxRate, got %v", err)
	}
}

func TestScanOptionsValidateNegativeWorkers(t *testing.T) {
	opts := ScanOptions{Workers: -1}
	err := opts.Validate()
	if !errors.Is(err, ErrInvalidScanOptions) {
		t.Errorf("expected ErrInvalidScanOptions for workers=-1, got %v", err)
	}
}

func TestScanOptionsValidateIdleScanNoZombie(t *testing.T) {
	opts := ScanOptions{ScanType: IdleScan}
	err := opts.Validate()
	if !errors.Is(err, ErrInvalidScanOptions) {
		t.Errorf("expected ErrInvalidScanOptions for idle scan without zombie, got %v", err)
	}
}

func TestScanOptionsValidateFTPBounceNoServer(t *testing.T) {
	opts := ScanOptions{ScanType: FTPBounceScan}
	err := opts.Validate()
	if !errors.Is(err, ErrInvalidScanOptions) {
		t.Errorf("expected ErrInvalidScanOptions for FTP bounce without server, got %v", err)
	}
}

func TestScanOptionsValidateOK(t *testing.T) {
	opts := ScanOptions{VersionIntensity: 5}
	err := opts.Validate()
	// May fail due to raw socket check but should not be ErrInvalidScanOptions
	if errors.Is(err, ErrInvalidScanOptions) {
		t.Errorf("unexpected ErrInvalidScanOptions for valid options: %v", err)
	}
}
