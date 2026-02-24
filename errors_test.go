package gomap

import (
	"errors"
	"testing"
)

func TestValidateIdleScanRequiresZombie(t *testing.T) {
	opts := ScanOptions{ScanType: IdleScan}
	err := opts.Validate()
	if err == nil {
		t.Fatal("expected error for idle scan without zombie")
	}
	if !errors.Is(err, ErrInvalidScanOptions) {
		t.Errorf("expected ErrInvalidScanOptions, got: %v", err)
	}
}

func TestValidateFTPBounceRequiresServer(t *testing.T) {
	opts := ScanOptions{ScanType: FTPBounceScan}
	err := opts.Validate()
	if err == nil {
		t.Fatal("expected error for FTP bounce without server")
	}
	if !errors.Is(err, ErrInvalidScanOptions) {
		t.Errorf("expected ErrInvalidScanOptions, got: %v", err)
	}
}

func TestValidateVersionIntensityRange(t *testing.T) {
	opts := ScanOptions{VersionIntensity: 10}
	err := opts.Validate()
	if err == nil {
		t.Fatal("expected error for intensity > 9")
	}
}

func TestValidateMinMaxRate(t *testing.T) {
	opts := ScanOptions{MinRate: 1000, MaxRate: 100}
	err := opts.Validate()
	if err == nil {
		t.Fatal("expected error when min-rate > max-rate")
	}
}

func TestValidateConnectScanOK(t *testing.T) {
	opts := ScanOptions{ScanType: ConnectScan}
	err := opts.Validate()
	if err != nil {
		t.Errorf("connect scan should validate: %v", err)
	}
}

func TestSentinelErrorsUsable(t *testing.T) {
	// Ensure sentinel errors can be used with errors.Is
	wrapped := errors.New("test")
	if errors.Is(wrapped, ErrRawSocketRequired) {
		t.Error("unrelated error should not match")
	}
}
