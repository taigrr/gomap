package gomap

import "testing"

func TestFingerprintToMap(t *testing.T) {
	fp := &OSFingerprint{
		SEQ: SEQFingerprint{
			SP: 0xFE, GCD: 1, ISR: 0xA8,
			TI: "I", CI: "I", II: "I", SS: "S", TS: "A",
		},
	}
	fp.OPS.Options = [6]string{"M5B4", "M5B4", "", "", "", ""}
	fp.WIN.Windows = [6]int{0xFFFF, 0xFFFF, 0, 0, 0, 0}
	fp.Probes[0] = ProbeFingerprint{
		Responded: true, DF: true, TTL: 64, Window: 0xFFFF,
		SeqBehavior: "A", AckBehavior: "S+", Flags: "AS", Options: "M5B4",
	}

	m := fingerprintToMap(fp)

	// SEQ
	if m["SEQ"]["SP"] != "FE" {
		t.Errorf("SEQ.SP = %q, want FE", m["SEQ"]["SP"])
	}
	if m["SEQ"]["TI"] != "I" {
		t.Errorf("SEQ.TI = %q, want I", m["SEQ"]["TI"])
	}

	// OPS
	if m["OPS"]["O1"] != "M5B4" {
		t.Errorf("OPS.O1 = %q, want M5B4", m["OPS"]["O1"])
	}

	// WIN
	if m["WIN"]["W1"] != "FFFF" {
		t.Errorf("WIN.W1 = %q, want FFFF", m["WIN"]["W1"])
	}

	// T1
	if m["T1"]["R"] != "Y" {
		t.Errorf("T1.R = %q, want Y", m["T1"]["R"])
	}
	if m["T1"]["DF"] != "Y" {
		t.Errorf("T1.DF = %q, want Y", m["T1"]["DF"])
	}
	if m["T1"]["F"] != "AS" {
		t.Errorf("T1.F = %q, want AS", m["T1"]["F"])
	}

	// U1 (not responded)
	if m["U1"]["R"] != "N" {
		t.Errorf("U1.R = %q, want N", m["U1"]["R"])
	}

	// IE (not responded)
	if m["IE"]["R"] != "N" {
		t.Errorf("IE.R = %q, want N", m["IE"]["R"])
	}

	// Verify all expected test keys exist
	for _, key := range []string{"SEQ", "OPS", "WIN", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "U1", "IE"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing key %s in fingerprint map", key)
		}
	}
}
