package probedb

import (
	"strings"
	"testing"
)

const testOSData = `# Test OS DB
This nmap-os-db is only valid for Nmap 7.94.2 and later

MatchPoints
SEQ(SP=25%GCD=75%ISR=25%TI=100%CI=50%II=100%SS=80%TS=100)
OPS(O1=20%O2=20%O3=20%O4=20%O5=20%O6=20)
WIN(W1=15%W2=15%W3=15%W4=15%W5=15%W6=15)
T1(R=100%DF=20%T=15%TG=15%S=20%A=20%F=30%RD=20%Q=20)

Fingerprint Linux 5.4
Class Linux | Linux | 5.X | general purpose
CPE cpe:/o:linux:linux_kernel:5.4
SEQ(SP=FE%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%SS=S%TS=A)
OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
T1(R=Y%DF=Y%T=40%TG=40%S=O%A=S+%F=AS%RD=0%Q=)

Fingerprint Windows 10
Class Microsoft | Windows | 10 | general purpose
CPE cpe:/o:microsoft:windows_10
SEQ(SP=100%GCD=1%ISR=108%TI=I%CI=I%II=I%SS=S%TS=U)
OPS(O1=M5B4NW8ST11%O2=M5B4NW8ST11%O3=M5B4NW8NNT11%O4=M5B4NW8ST11%O5=M5B4NW8ST11%O6=M5B4NW8ST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
T1(R=Y%DF=Y%T=80%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
`

func TestParseOSDB(t *testing.T) {
	db, err := ParseOSDB(strings.NewReader(testOSData))
	if err != nil {
		t.Fatalf("ParseOSDB error: %v", err)
	}

	if len(db.Fingerprints) != 2 {
		t.Fatalf("expected 2 fingerprints, got %d", len(db.Fingerprints))
	}

	// MatchPoints
	if len(db.MatchPoints.Points) == 0 {
		t.Error("MatchPoints should not be empty")
	}
	seqPoints := db.MatchPoints.Points["SEQ"]
	if seqPoints == nil {
		t.Fatal("SEQ match points missing")
	}
	if seqPoints["SP"] != 25 {
		t.Errorf("SEQ.SP points = %d, want 25", seqPoints["SP"])
	}
	if seqPoints["TI"] != 100 {
		t.Errorf("SEQ.TI points = %d, want 100", seqPoints["TI"])
	}

	// Linux fingerprint
	linux := db.Fingerprints[0]
	if linux.Name != "Linux 5.4" {
		t.Errorf("name = %q, want 'Linux 5.4'", linux.Name)
	}
	if len(linux.Classes) != 1 {
		t.Fatalf("expected 1 class, got %d", len(linux.Classes))
	}
	if linux.Classes[0].Vendor != "Linux" {
		t.Errorf("vendor = %q", linux.Classes[0].Vendor)
	}
	if linux.Classes[0].Family != "Linux" {
		t.Errorf("family = %q", linux.Classes[0].Family)
	}
	if linux.Classes[0].Generation != "5.X" {
		t.Errorf("generation = %q", linux.Classes[0].Generation)
	}
	if len(linux.CPE) != 1 || linux.CPE[0] != "cpe:/o:linux:linux_kernel:5.4" {
		t.Errorf("CPE = %v", linux.CPE)
	}
	if linux.Tests["SEQ"]["TI"] != "Z" {
		t.Errorf("SEQ.TI = %q, want Z", linux.Tests["SEQ"]["TI"])
	}

	// Windows fingerprint
	win := db.Fingerprints[1]
	if win.Name != "Windows 10" {
		t.Errorf("name = %q", win.Name)
	}
	if win.Tests["T1"]["T"] != "80" {
		t.Errorf("T1.T = %q, want 80", win.Tests["T1"]["T"])
	}
}

func TestMatchOS(t *testing.T) {
	db, err := ParseOSDB(strings.NewReader(testOSData))
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Create a fingerprint that matches Linux
	fp := map[string]map[string]string{
		"SEQ": {"SP": "FE", "GCD": "1", "ISR": "10A", "TI": "Z", "CI": "Z", "II": "I", "SS": "S", "TS": "A"},
		"T1":  {"R": "Y", "DF": "Y", "T": "40", "TG": "40", "S": "O", "A": "S+", "F": "AS", "RD": "0", "Q": ""},
	}

	results := db.MatchOS(fp)
	if len(results) == 0 {
		t.Fatal("expected at least one match")
	}

	if results[0].Name != "Linux 5.4" {
		t.Errorf("best match = %q, want 'Linux 5.4'", results[0].Name)
	}
	if results[0].Accuracy < 0.5 {
		t.Errorf("accuracy = %.2f, expected > 0.5", results[0].Accuracy)
	}

	t.Logf("Best match: %s (accuracy: %.1f%%)", results[0].Name, results[0].Accuracy*100)
}

func TestMatchAttributeValue(t *testing.T) {
	tests := []struct {
		actual   string
		expected string
		want     bool
	}{
		{"Z", "Z", true},
		{"Z", "I", false},
		{"40", "3E-42", true},   // hex range
		{"3D", "3E-42", false},  // below range
		{"43", "3E-42", false},  // above range
		{"Z", "Z|I|RI", true},  // alternatives
		{"I", "Z|I|RI", true},
		{"X", "Z|I|RI", false},
	}
	for _, tt := range tests {
		got := matchAttributeValue(tt.actual, tt.expected)
		if got != tt.want {
			t.Errorf("matchAttributeValue(%q, %q) = %v, want %v", tt.actual, tt.expected, got, tt.want)
		}
	}
}
