package gomap

import "testing"

func TestOSScanThresholds(t *testing.T) {
	if OSScanGuessThreshold <= OSScanGuessAggressiveThreshold {
		t.Errorf("default threshold (%f) should be > aggressive (%f)",
			OSScanGuessThreshold, OSScanGuessAggressiveThreshold)
	}
	if OSScanGuessThreshold != 0.85 {
		t.Errorf("default threshold should be 0.85 (nmap compat), got %f", OSScanGuessThreshold)
	}
}
