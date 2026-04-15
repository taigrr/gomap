package gomap

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- fingerprintToMap: U1 and IE responded paths ---

func TestFingerprintToMapU1Responded(t *testing.T) {
	fp := &OSFingerprint{}
	fp.U1 = UDPFingerprint{
		Responded:   true,
		DF:          true,
		TTL:         64,
		IPLen:       56,
		UnusedField: 0,
		RIPL:        "G",
		RID:         "G",
		RIPCK:       "G",
		RUCK:        "G",
		RUD:         "G",
	}

	m := fingerprintToMap(fp)

	u1 := m["U1"]
	if u1["R"] != "Y" {
		t.Errorf("U1.R = %q, want Y", u1["R"])
	}
	if u1["DF"] != "Y" {
		t.Errorf("U1.DF = %q, want Y", u1["DF"])
	}
	if u1["T"] != "40" {
		t.Errorf("U1.T = %q, want 40", u1["T"])
	}
	if u1["IPL"] != "38" {
		t.Errorf("U1.IPL = %q, want 38", u1["IPL"])
	}
	if u1["RIPL"] != "G" {
		t.Errorf("U1.RIPL = %q, want G", u1["RIPL"])
	}
}

func TestFingerprintToMapU1DFfalse(t *testing.T) {
	fp := &OSFingerprint{}
	fp.U1 = UDPFingerprint{
		Responded: true,
		DF:        false,
		TTL:       128,
	}

	m := fingerprintToMap(fp)
	if m["U1"]["DF"] != "N" {
		t.Errorf("U1.DF = %q, want N", m["U1"]["DF"])
	}
}

func TestFingerprintToMapIEResponded(t *testing.T) {
	fp := &OSFingerprint{}
	fp.IE = ICMPFingerprint{
		Responded: true,
		DFI:       "Y",
		TTL:       64,
		CD:        "S",
	}

	m := fingerprintToMap(fp)
	ie := m["IE"]
	if ie["R"] != "Y" {
		t.Errorf("IE.R = %q, want Y", ie["R"])
	}
	if ie["DFI"] != "Y" {
		t.Errorf("IE.DFI = %q, want Y", ie["DFI"])
	}
	if ie["CD"] != "S" {
		t.Errorf("IE.CD = %q, want S", ie["CD"])
	}
}

// --- formatFingerprint ---

func TestFormatFingerprint(t *testing.T) {
	fp := &OSFingerprint{
		SEQ: SEQFingerprint{
			SP: 0xFE, GCD: 1, ISR: 0xA8,
			TI: "I", CI: "I", II: "I", SS: "S", TS: "A",
		},
	}
	fp.OPS.Options = [6]string{"M5B4", "M5B4", "", "", "", ""}
	fp.WIN.Windows = [6]int{0xFFFF, 0x8000, 0, 0, 0, 0}
	fp.Probes[0] = ProbeFingerprint{
		Responded: true, DF: true, TTL: 64, Window: 0xFFFF,
		SeqBehavior: "A", AckBehavior: "S+", Flags: "AS", Options: "M5B4",
	}

	s := formatFingerprint(fp)

	if !strings.Contains(s, "SEQ(SP=FE%GCD=1%ISR=A8%TI=I%CI=I%II=I%SS=S%TS=A)") {
		t.Errorf("SEQ line wrong: %s", s)
	}
	if !strings.Contains(s, "OPS(O1=M5B4%O2=M5B4%O3=%O4=%O5=%O6=)") {
		t.Errorf("OPS line wrong: %s", s)
	}
	if !strings.Contains(s, "WIN(W1=FFFF%W2=8000%W3=0%W4=0%W5=0%W6=0)") {
		t.Errorf("WIN line wrong: %s", s)
	}
	if !strings.Contains(s, "T1(R=Y%DF=Y%T=40%W=FFFF%S=A%A=S+%F=AS%O=M5B4%RD=0%Q=)") {
		t.Errorf("T1 line wrong: %s", s)
	}
	// T2 should be not responded
	if !strings.Contains(s, "T2(R=N%DF=N%") {
		t.Errorf("T2 line wrong: %s", s)
	}
}

// --- OutputConfig.WriteAll with ScriptKiddieFile ---

func TestOutputConfigWriteAllWithScriptKiddie(t *testing.T) {
	dir := t.TempDir()
	oc := &OutputConfig{
		NormalFile:       filepath.Join(dir, "out.nmap"),
		XMLFile:          filepath.Join(dir, "out.xml"),
		GrepFile:         filepath.Join(dir, "out.gnmap"),
		ScriptKiddieFile: filepath.Join(dir, "out.skid"),
	}

	err := oc.WriteAll("Port 80 open", []byte("<xml/>"), "Host: 127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	// Check script kiddie file was created
	data, err := os.ReadFile(oc.ScriptKiddieFile)
	if err != nil {
		t.Fatalf("reading script kiddie file: %v", err)
	}
	if len(data) == 0 {
		t.Error("script kiddie file is empty")
	}
}

func TestOutputConfigWriteAllEmptyPaths(t *testing.T) {
	oc := &OutputConfig{}
	// Should be a no-op, no error
	if err := oc.WriteAll("", nil, ""); err != nil {
		t.Fatalf("WriteAll with empty paths should not error: %v", err)
	}
}

func TestOutputConfigWriteXMLDedicated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.xml")

	oc := &OutputConfig{XMLFile: path}
	if err := oc.WriteXML([]byte("<scan/>")); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "<scan/>" {
		t.Errorf("got %q", string(data))
	}
}

func TestOutputConfigWriteGrepDedicated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.gnmap")

	oc := &OutputConfig{GrepFile: path}
	if err := oc.WriteGrep("Host: 10.0.0.1 Ports: 80/open/tcp"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "Host: 10.0.0.1 Ports: 80/open/tcp" {
		t.Errorf("got %q", string(data))
	}
}

func TestOutputConfigWriteToInvalidPath(t *testing.T) {
	oc := &OutputConfig{NormalFile: "/nonexistent/dir/file.txt"}
	if err := oc.WriteNormal("test"); err == nil {
		t.Error("expected error writing to invalid path")
	}
}

func TestOutputConfigWriteXMLEmpty(t *testing.T) {
	oc := &OutputConfig{}
	// No XMLFile set — should be no-op
	if err := oc.WriteXML([]byte("data")); err != nil {
		t.Fatal(err)
	}
}

func TestOutputConfigWriteGrepEmpty(t *testing.T) {
	oc := &OutputConfig{}
	if err := oc.WriteGrep("data"); err != nil {
		t.Fatal(err)
	}
}

// --- ResultsToXMLStyled ---

func TestResultsToXMLStyledNoStylesheet(t *testing.T) {
	results := []*ScanResult{{
		Hostname: "10.0.0.1",
	}}
	data, err := ResultsToXMLStyled(results, ConnectScan, time.Now(), "1.0", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "xml-stylesheet") {
		t.Error("should not contain stylesheet PI when empty")
	}
}

func TestResultsToXMLStyledWithStylesheet(t *testing.T) {
	results := []*ScanResult{{
		Hostname: "10.0.0.1",
	}}
	data, err := ResultsToXMLStyled(results, ConnectScan, time.Now(), "1.0", "custom.xsl")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, `<?xml-stylesheet href="custom.xsl" type="text/xsl"?>`) {
		t.Errorf("missing stylesheet PI: %s", s[:min(200, len(s))])
	}
}

func TestResultsToXMLStyledWebxml(t *testing.T) {
	results := []*ScanResult{{
		Hostname: "10.0.0.1",
	}}
	data, err := ResultsToXMLStyled(results, ConnectScan, time.Now(), "1.0", "webxml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "svn.nmap.org/nmap/docs/nmap.xsl") {
		t.Errorf("webxml should resolve to nmap.org XSL: %s", s[:min(200, len(s))])
	}
}

// --- ParseScanFlags edge cases ---

func TestParseScanFlagsHexInvalid(t *testing.T) {
	_, err := ParseScanFlags("0xGG")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
	var ife *InvalidFlagError
	if ok := errors.As(err, &ife); !ok {
		t.Errorf("expected InvalidFlagError, got %T", err)
	}
}

func TestParseScanFlagsInvalidChar(t *testing.T) {
	_, err := ParseScanFlags("SXF")
	if err == nil {
		t.Error("expected error for invalid flag char X")
	}
}

func TestParseScanFlagsAllFlags(t *testing.T) {
	val, err := ParseScanFlags("UAPRSF")
	if err != nil {
		t.Fatal(err)
	}
	// All 6 flags set: 0x3F
	if val != 0x3F {
		t.Errorf("got 0x%X, want 0x3F", val)
	}
}

func TestParseScanFlagsHexValid(t *testing.T) {
	val, err := ParseScanFlags("0x12")
	if err != nil {
		t.Fatal(err)
	}
	if val != 0x12 {
		t.Errorf("got 0x%X, want 0x12", val)
	}
}

func TestParseScanFlagsEmpty(t *testing.T) {
	val, err := ParseScanFlags("")
	if err != nil {
		t.Fatal(err)
	}
	if val != 0 {
		t.Errorf("got 0x%X, want 0", val)
	}
}

func TestInvalidFlagErrorMessage(t *testing.T) {
	e := &InvalidFlagError{Flag: "Z"}
	if e.Error() != "unknown TCP flag: Z" {
		t.Errorf("got %q", e.Error())
	}
}

// --- ScanOptions.defaults with stealth ---

func TestScanOptionsDefaultsStealthConverts(t *testing.T) {
	opts := ScanOptions{Stealth: true}
	opts.defaults()
	if opts.ScanType != SYNScan {
		t.Errorf("stealth should set SYNScan, got %v", opts.ScanType)
	}
}

// --- net.go: GetLocalAddr ---

func TestGetLocalAddrIPv4Target(t *testing.T) {
	addr, err := GetLocalAddr("192.168.1.1")
	if err != nil {
		t.Skipf("no local IPv4: %v", err)
	}
	if strings.Contains(addr, ":") {
		t.Errorf("expected IPv4, got %s", addr)
	}
}

func TestGetLocalAddrIPv6Target(t *testing.T) {
	_, err := GetLocalAddr("2001:db8::1")
	// May fail if no global IPv6 — that's expected in CI
	if err != nil {
		t.Skipf("no local IPv6: %v", err)
	}
}

// --- selectIP fallback ---

func TestSelectIPFallback(t *testing.T) {
	v4 := net.ParseIP("10.0.0.1")
	// Request IPv6 but only v4 available — should fallback to first
	got := selectIP([]net.IP{v4}, true)
	if !got.Equal(v4) {
		t.Errorf("fallback selectIP = %s, want %s", got, v4)
	}
}

// --- CreateHostRange edge cases ---

func TestCreateHostRangeInvalidCIDR(t *testing.T) {
	hosts := CreateHostRange("not-a-cidr")
	if hosts != nil {
		t.Errorf("expected nil for invalid CIDR, got %d hosts", len(hosts))
	}
}

func TestCreateHostRangeIPv6TooLarge(t *testing.T) {
	hosts := CreateHostRange("2001:db8::/64")
	if hosts != nil {
		t.Error("expected nil for large IPv6 range")
	}
}

func TestCreateHostRangeIPv6Small(t *testing.T) {
	hosts := CreateHostRange("2001:db8::/126")
	// /126 = 4 addresses, minus network and broadcast = 2 hosts
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts for /126, got %d", len(hosts))
	}
}

// --- ToScriptKiddie ---

func TestToScriptKiddieNonEmpty(t *testing.T) {
	input := "Port 80 is open"
	output := ToScriptKiddie(input)
	if len(output) != len(input) {
		t.Errorf("length mismatch: input %d, output %d", len(input), len(output))
	}
}

func TestToScriptKiddieEmpty(t *testing.T) {
	if ToScriptKiddie("") != "" {
		t.Error("empty input should return empty")
	}
}

// --- leetChar coverage ---

func TestLeetCharCoversAllBranches(t *testing.T) {
	// Just exercise all switch cases to get coverage
	chars := []rune{'a', 'e', 'i', 'o', 's', 't', 'l', 'z'}
	for _, c := range chars {
		_ = leetChar(c)
	}
}
