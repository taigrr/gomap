package probedb

import (
	"os"
	"strings"
	"testing"
)

const testProbeData = `# Test probes
Exclude T:9100-9107

Probe TCP NULL q||
totalwaitms 6000
tcpwrappedms 3000
match ssh m|^SSH-([\d.]+)-OpenSSH[_-]([\w.]+)| p/OpenSSH/ v/$2/ i/protocol $1/
match ftp m|^220[- ](.*)FTP| p/FTP server/ i/$1/
softmatch http m|^HTTP/| p/HTTP server/

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports 80,443,8080,8443
sslports 443,8443
totalwaitms 5000
match http m|^HTTP/1\.[01] (\d+)| p/HTTP server/ v/$1/
match http m|Server: Apache/(\S+)| p/Apache httpd/ v/$1/ cpe:/a:apache:http_server:$1/

Probe UDP DNSVersionBindReq q|\0\x06\x01\0\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03|
rarity 1
ports 53
match dns m|version\.bind.*\x04\x05(\S+)|s p/ISC BIND/ v/$1/
`

func TestParseServiceProbes(t *testing.T) {
	db, err := ParseServiceProbes(strings.NewReader(testProbeData))
	if err != nil {
		t.Fatalf("ParseServiceProbes error: %v", err)
	}

	if len(db.Probes) != 3 {
		t.Fatalf("expected 3 probes, got %d", len(db.Probes))
	}

	// Exclude ports
	if !db.ExcludePorts.Contains(9100) {
		t.Error("9100 should be excluded")
	}
	if !db.ExcludePorts.Contains(9107) {
		t.Error("9107 should be excluded")
	}
	if db.ExcludePorts.Contains(9108) {
		t.Error("9108 should not be excluded")
	}

	// NULL probe
	null := db.Probes[0]
	if null.Name != "NULL" {
		t.Errorf("first probe name = %q, want NULL", null.Name)
	}
	if null.Protocol != "TCP" {
		t.Errorf("NULL protocol = %q, want TCP", null.Protocol)
	}
	if len(null.ProbeString) != 0 {
		t.Errorf("NULL probe string should be empty, got %d bytes", len(null.ProbeString))
	}
	if null.TotalWaitMS != 6000 {
		t.Errorf("NULL totalwaitms = %d, want 6000", null.TotalWaitMS)
	}
	if len(null.Matches) != 2 {
		t.Errorf("NULL matches = %d, want 2", len(null.Matches))
	}
	if len(null.SoftMatches) != 1 {
		t.Errorf("NULL softmatches = %d, want 1", len(null.SoftMatches))
	}

	// GetRequest probe
	get := db.Probes[1]
	if get.Name != "GetRequest" {
		t.Errorf("second probe name = %q, want GetRequest", get.Name)
	}
	if get.Rarity != 1 {
		t.Errorf("GetRequest rarity = %d, want 1", get.Rarity)
	}
	if !get.Ports.Contains(80) {
		t.Error("GetRequest should include port 80")
	}
	if !get.SSLPorts.Contains(443) {
		t.Error("GetRequest should include SSL port 443")
	}
	if len(get.ProbeString) == 0 {
		t.Error("GetRequest probe string should not be empty")
	}
	// Verify decoded: "GET / HTTP/1.0\r\n\r\n"
	expected := "GET / HTTP/1.0\r\n\r\n"
	if string(get.ProbeString) != expected {
		t.Errorf("GetRequest probe = %q, want %q", string(get.ProbeString), expected)
	}

	// DNS probe
	dns := db.Probes[2]
	if dns.Protocol != "UDP" {
		t.Errorf("DNS protocol = %q, want UDP", dns.Protocol)
	}
}

func TestMatchPatterns(t *testing.T) {
	db, err := ParseServiceProbes(strings.NewReader(testProbeData))
	if err != nil {
		t.Fatalf("ParseServiceProbes error: %v", err)
	}

	null := db.Probes[0]

	// Test SSH match
	sshBanner := []byte("SSH-2.0-OpenSSH_9.0p1\r\n")
	matched := false
	for _, m := range null.Matches {
		if m.Pattern.Match(sshBanner) {
			matched = true
			if m.Service != "ssh" {
				t.Errorf("matched service = %q, want ssh", m.Service)
			}

			// Test version extraction
			groups := m.Pattern.FindStringSubmatch(string(sshBanner))
			vi := m.VersionInfo.Apply(groups)
			if vi.ProductName != "OpenSSH" {
				t.Errorf("product = %q, want OpenSSH", vi.ProductName)
			}
			if vi.Version != "9.0p1" {
				t.Errorf("version = %q, want 9.0p1", vi.Version)
			}
			if vi.Info != "protocol 2.0" {
				t.Errorf("info = %q, want 'protocol 2.0'", vi.Info)
			}
			break
		}
	}
	if !matched {
		t.Error("SSH banner should have matched")
	}
}

func TestMatchCPE(t *testing.T) {
	db, err := ParseServiceProbes(strings.NewReader(testProbeData))
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	get := db.Probes[1]

	response := []byte("HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n")
	for _, m := range get.Matches {
		groups := m.Pattern.FindStringSubmatch(string(response))
		if groups != nil && len(m.VersionInfo.CPE) > 0 {
			vi := m.VersionInfo.Apply(groups)
			if len(vi.CPE) == 0 {
				t.Error("expected CPE entries after apply")
			}
			if vi.CPE[0] != "cpe:/a:apache:http_server:2.4.52" {
				t.Errorf("CPE = %q, want cpe:/a:apache:http_server:2.4.52", vi.CPE[0])
			}
			return
		}
	}
	t.Error("Apache response should have matched with CPE")
}

func TestDecodeEscapes(t *testing.T) {
	tests := []struct {
		input string
		want  []byte
	}{
		{`\r\n`, []byte{'\r', '\n'}},
		{`\x00\x01\xff`, []byte{0x00, 0x01, 0xff}},
		{`hello`, []byte("hello")},
		{`\\`, []byte{'\\'}},
		{`\t\0\a`, []byte{'\t', 0, '\a'}},
		{`GET / HTTP/1.0\r\n\r\n`, append([]byte("GET / HTTP/1.0"), '\r', '\n', '\r', '\n')},
	}
	for _, tt := range tests {
		got := decodeEscapes(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("decodeEscapes(%q) len = %d, want %d", tt.input, len(got), len(tt.want))
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("decodeEscapes(%q)[%d] = %02x, want %02x", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestPortSet(t *testing.T) {
	ps := NewPortSet("80,443,8080-8085,9000")

	if !ps.Contains(80) {
		t.Error("should contain 80")
	}
	if !ps.Contains(443) {
		t.Error("should contain 443")
	}
	if !ps.Contains(8082) {
		t.Error("should contain 8082")
	}
	if !ps.Contains(9000) {
		t.Error("should contain 9000")
	}
	if ps.Contains(81) {
		t.Error("should not contain 81")
	}
	if ps.Contains(8086) {
		t.Error("should not contain 8086")
	}
}

func TestPortSetEmpty(t *testing.T) {
	ps := NewPortSet("")
	if ps.Len() != 0 {
		t.Errorf("empty port set len = %d, want 0", ps.Len())
	}
}

func TestProbesForPort(t *testing.T) {
	db, err := ParseServiceProbes(strings.NewReader(testProbeData))
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	probes := db.ProbesForPort(80, "TCP")
	if len(probes) < 2 {
		t.Fatalf("expected at least 2 probes for port 80 TCP, got %d", len(probes))
	}
	if probes[0].Name != "NULL" {
		t.Errorf("first probe should be NULL, got %s", probes[0].Name)
	}

	// Port 9100 should be excluded
	excluded := db.ProbesForPort(9100, "TCP")
	if len(excluded) != 0 {
		t.Errorf("port 9100 should be excluded, got %d probes", len(excluded))
	}

	// UDP probes
	udp := db.ProbesForPort(53, "UDP")
	if len(udp) != 1 {
		t.Errorf("expected 1 UDP probe for port 53, got %d", len(udp))
	}
}

func TestVersionInfoApply(t *testing.T) {
	vi := VersionInfo{
		ProductName: "Server $1",
		Version:     "$2",
		Info:        "running $1 version $2",
		CPE:         []string{"cpe:/a:vendor:$1:$2"},
	}

	groups := []string{"full match", "Apache", "2.4.52"}
	result := vi.Apply(groups)

	if result.ProductName != "Server Apache" {
		t.Errorf("ProductName = %q", result.ProductName)
	}
	if result.Version != "2.4.52" {
		t.Errorf("Version = %q", result.Version)
	}
	if result.Info != "running Apache version 2.4.52" {
		t.Errorf("Info = %q", result.Info)
	}
	if len(result.CPE) != 1 || result.CPE[0] != "cpe:/a:vendor:Apache:2.4.52" {
		t.Errorf("CPE = %v", result.CPE)
	}
}

// Test with actual nmap-service-probes if available
func TestParseRealServiceProbes(t *testing.T) {
	path := "/tmp/nmap-ref/nmap-service-probes"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("nmap-service-probes not found at %s", path)
	}

	db, err := LoadServiceProbesFile(path)
	if err != nil {
		t.Fatalf("LoadServiceProbesFile error: %v", err)
	}

	if len(db.Probes) < 100 {
		t.Errorf("expected at least 100 probes, got %d", len(db.Probes))
	}

	totalMatches := 0
	for _, p := range db.Probes {
		totalMatches += len(p.Matches) + len(p.SoftMatches)
	}
	if totalMatches < 10000 {
		t.Errorf("expected at least 10000 match patterns, got %d", totalMatches)
	}

	t.Logf("%s", db.Stats())
}

// Test with actual nmap-os-db if available
func TestParseRealOSDB(t *testing.T) {
	path := "/tmp/nmap-ref/nmap-os-db"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("nmap-os-db not found at %s", path)
	}

	db, err := LoadOSDBFile(path)
	if err != nil {
		t.Fatalf("LoadOSDBFile error: %v", err)
	}

	if len(db.Fingerprints) < 5000 {
		t.Errorf("expected at least 5000 fingerprints, got %d", len(db.Fingerprints))
	}

	t.Logf("%s", db.Stats())
}
