package gomap

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Service Lookup Tests ---

func TestLookupService(t *testing.T) {
	tests := []struct {
		port    int
		wantNot string // should NOT be this value
	}{
		{22, "unknown"},
		{80, "unknown"},
		{443, "unknown"},
	}
	for _, tt := range tests {
		got := LookupService(tt.port)
		if got == tt.wantNot {
			t.Errorf("LookupService(%d) = %q, should not be %q", tt.port, got, tt.wantNot)
		}
	}

	// Unknown port should return "unknown"
	if got := LookupService(99999); got != "unknown" {
		t.Errorf("LookupService(99999) = %q, want %q", got, "unknown")
	}
}

func TestLookupUDPService(t *testing.T) {
	svc := LookupUDPService(53)
	if svc == "unknown" {
		t.Error("expected a service name for UDP port 53, got unknown")
	}

	if got := LookupUDPService(99999); got != "unknown" {
		t.Errorf("LookupUDPService(99999) = %q, want unknown", got)
	}
}

func TestLookupServiceConcurrent(t *testing.T) {
	// Verify lookup is safe for concurrent use
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			_ = LookupService(port)
			_ = LookupUDPService(port)
		}(i)
	}
	wg.Wait()
}

// --- Network Utility Tests ---

func TestCreateHostRange(t *testing.T) {
	tests := []struct {
		cidr      string
		wantLen   int
		wantNil   bool
		wantFirst string
	}{
		{"192.168.1.0/30", 2, false, "192.168.1.1"},
		{"10.0.0.0/30", 2, false, "10.0.0.1"},
		{"not-a-cidr", 0, true, ""},
		{"192.168.1.0/32", 0, false, ""}, // single host, no range
	}
	for _, tt := range tests {
		hosts := CreateHostRange(tt.cidr)
		if tt.wantNil && hosts != nil {
			t.Errorf("CreateHostRange(%q) = %v, want nil", tt.cidr, hosts)
			continue
		}
		if !tt.wantNil && len(hosts) != tt.wantLen {
			t.Errorf("CreateHostRange(%q) len = %d, want %d", tt.cidr, len(hosts), tt.wantLen)
		}
		if tt.wantFirst != "" && len(hosts) > 0 && hosts[0] != tt.wantFirst {
			t.Errorf("CreateHostRange(%q)[0] = %q, want %q", tt.cidr, hosts[0], tt.wantFirst)
		}
	}
}

func TestGetLocalIP(t *testing.T) {
	ip, err := GetLocalIP()
	if err != nil {
		t.Skipf("No local IP found: %v", err)
	}
	if ip == "" {
		t.Error("GetLocalIP returned empty string")
	}
	// Should be a valid IPv4
	if net.ParseIP(ip) == nil {
		t.Errorf("GetLocalIP returned invalid IP: %s", ip)
	}
}

func TestGetLocalRange(t *testing.T) {
	r := GetLocalRange()
	if r == "" {
		t.Error("GetLocalRange returned empty string")
	}
	// Should be valid CIDR
	_, _, err := net.ParseCIDR(r)
	if err != nil {
		t.Errorf("GetLocalRange returned invalid CIDR %q: %v", r, err)
	}
}

// --- ScanType Tests ---

func TestScanTypeString(t *testing.T) {
	tests := []struct {
		st   ScanType
		want string
	}{
		{ConnectScan, "connect"},
		{SYNScan, "syn"},
		{FINScan, "fin"},
		{XmasScan, "xmas"},
		{NullScan, "null"},
		{ACKScan, "ack"},
		{WindowScan, "window"},
		{UDPScan, "udp"},
		{ScanType(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.st.String(); got != tt.want {
			t.Errorf("ScanType(%d).String() = %q, want %q", tt.st, got, tt.want)
		}
	}
}

func TestScanTypeRequiresRawSocket(t *testing.T) {
	rawTypes := []ScanType{SYNScan, FINScan, XmasScan, NullScan, ACKScan, WindowScan}
	for _, st := range rawTypes {
		if !st.RequiresRawSocket() {
			t.Errorf("%s should require raw socket", st)
		}
	}

	noRawTypes := []ScanType{ConnectScan, UDPScan}
	for _, st := range noRawTypes {
		if st.RequiresRawSocket() {
			t.Errorf("%s should not require raw socket", st)
		}
	}
}

// --- PortState Tests ---

func TestPortStateString(t *testing.T) {
	tests := []struct {
		ps   PortState
		want string
	}{
		{PortOpen, "open"},
		{PortClosed, "closed"},
		{PortFiltered, "filtered"},
		{PortUnfiltered, "unfiltered"},
		{PortOpenFiltered, "open|filtered"},
		{PortState(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.ps.String(); got != tt.want {
			t.Errorf("PortState(%d).String() = %q, want %q", tt.ps, got, tt.want)
		}
	}
}

// --- ScanResult Tests ---

func TestScanResultOpenPorts(t *testing.T) {
	r := &ScanResult{
		Ports: []PortResult{
			{Port: 22, Open: true, State: PortOpen, Service: "ssh"},
			{Port: 80, Open: false, State: PortClosed, Service: "http"},
			{Port: 443, Open: true, State: PortOpen, Service: "https"},
		},
	}
	open := r.OpenPorts()
	if len(open) != 2 {
		t.Errorf("expected 2 open ports, got %d", len(open))
	}
	if !r.HasOpenPorts() {
		t.Error("HasOpenPorts should be true")
	}
}

func TestScanResultNoOpenPorts(t *testing.T) {
	r := &ScanResult{
		Ports: []PortResult{
			{Port: 22, Open: false, State: PortClosed},
			{Port: 80, Open: false, State: PortClosed},
		},
	}
	if r.HasOpenPorts() {
		t.Error("HasOpenPorts should be false")
	}
	if len(r.OpenPorts()) != 0 {
		t.Error("OpenPorts should be empty")
	}
}

func TestScanResultString(t *testing.T) {
	r := &ScanResult{
		Hostname: "localhost",
		IP:       []net.IP{net.IPv4(127, 0, 0, 1)},
		Ports: []PortResult{
			{Port: 22, Open: true, State: PortOpen, Service: "ssh"},
			{Port: 80, Open: false, State: PortClosed, Service: "http"},
		},
	}
	s := r.String()
	if s == "" {
		t.Error("String() returned empty")
	}
	if !strings.Contains(s, "localhost") {
		t.Error("String() should contain hostname")
	}
	if !strings.Contains(s, "22") {
		t.Error("String() should contain port 22")
	}
}

func TestScanResultJSON(t *testing.T) {
	r := &ScanResult{
		Hostname: "test.example.com",
		IP:       []net.IP{net.IPv4(10, 0, 0, 1)},
		Ports: []PortResult{
			{Port: 80, Open: true, State: PortOpen, Service: "http"},
		},
	}

	j, err := r.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}

	var parsed JSONResult
	if err := json.Unmarshal([]byte(j), &parsed); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	if parsed.IP != "10.0.0.1" {
		t.Errorf("JSON IP = %q, want 10.0.0.1", parsed.IP)
	}
	if parsed.Hostname != "test.example.com" {
		t.Errorf("JSON Hostname = %q, want test.example.com", parsed.Hostname)
	}
	if !parsed.Active {
		t.Error("JSON Active should be true")
	}
	if len(parsed.Ports) != 1 {
		t.Errorf("JSON Ports len = %d, want 1", len(parsed.Ports))
	}
}

func TestRangeScanResultJSON(t *testing.T) {
	results := RangeScanResult{
		{
			Hostname: "host1",
			IP:       []net.IP{net.IPv4(10, 0, 0, 1)},
			Ports:    []PortResult{{Port: 22, Open: true, Service: "ssh"}},
		},
		{
			Hostname: "host2",
			IP:       []net.IP{net.IPv4(10, 0, 0, 2)},
			Ports:    []PortResult{{Port: 80, Open: false, Service: "http"}},
		},
	}

	j, err := results.JSON()
	if err != nil {
		t.Fatalf("RangeScanResult.JSON() error: %v", err)
	}

	var parsed []JSONResult
	if err := json.Unmarshal([]byte(j), &parsed); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}
	if len(parsed) != 2 {
		t.Errorf("expected 2 results, got %d", len(parsed))
	}
}

// --- ScanOptions Tests ---

func TestScanOptionsDefaults(t *testing.T) {
	opts := ScanOptions{}
	opts.defaults()

	if opts.Timeout != 3*time.Second {
		t.Errorf("default timeout = %v, want 3s", opts.Timeout)
	}
	if opts.Workers != 500 {
		t.Errorf("default workers = %d, want 500", opts.Workers)
	}
}

func TestScanOptionsDefaultsFastScan(t *testing.T) {
	opts := ScanOptions{FastScan: true}
	opts.defaults()
	if opts.Workers != 50 {
		t.Errorf("fast scan workers = %d, want 50", opts.Workers)
	}
}

func TestScanOptionsStealthBackcompat(t *testing.T) {
	opts := ScanOptions{Stealth: true}
	opts.defaults()
	if opts.ScanType != SYNScan {
		t.Errorf("Stealth=true should set ScanType to SYNScan, got %s", opts.ScanType)
	}
}

func TestScanOptionsProtocol(t *testing.T) {
	tcp := ScanOptions{ScanType: ConnectScan}
	if tcp.protocol() != "tcp" {
		t.Errorf("ConnectScan protocol = %q, want tcp", tcp.protocol())
	}

	udp := ScanOptions{ScanType: UDPScan}
	if udp.protocol() != "udp" {
		t.Errorf("UDPScan protocol = %q, want udp", udp.protocol())
	}
}

// --- Context Cancellation Tests ---

func TestScanHostContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := ScanHost(ctx, "192.0.2.1", ScanOptions{
		Timeout: 100 * time.Millisecond,
		Ports:   []int{80},
	})
	// Should either return context error or empty results quickly
	// The key test is that it doesn't hang
	_ = err
}

func TestScanCIDRContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ScanCIDR(ctx, "192.0.2.0/30", ScanOptions{
		Timeout: 100 * time.Millisecond,
		Ports:   []int{80},
	})
	_ = err
}

func TestDiscoverHostsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := DiscoverHosts(ctx, []string{"192.0.2.1"}, DiscoveryOptions{
		Timeout: 100 * time.Millisecond,
	})
	_ = err
	// Should return quickly without hanging
	for _, r := range results {
		if r.Alive {
			t.Error("cancelled context should not find alive hosts")
		}
	}
}

// --- Connect Scan Integration Test ---

func TestScanPortConnectLocalhost(t *testing.T) {
	// Start a TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start listener: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	// Accept connections in background
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	ctx := context.Background()
	result, err := ScanHost(ctx, "127.0.0.1", ScanOptions{
		Ports:   []int{port},
		Timeout: 2 * time.Second,
		Workers: 1,
	})
	if err != nil {
		t.Fatalf("ScanHost error: %v", err)
	}

	if len(result.Ports) != 1 {
		t.Fatalf("expected 1 port result, got %d", len(result.Ports))
	}

	if !result.Ports[0].Open {
		t.Errorf("port %d should be open", port)
	}
	if result.Ports[0].State != PortOpen {
		t.Errorf("port %d state = %s, want open", port, result.Ports[0].State)
	}
}

func TestScanPortConnectClosedPort(t *testing.T) {
	// Find a port that's definitely closed
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start listener: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // close it immediately so it's unused

	ctx := context.Background()
	result, err := ScanHost(ctx, "127.0.0.1", ScanOptions{
		Ports:   []int{port},
		Timeout: 1 * time.Second,
		Workers: 1,
	})
	if err != nil {
		t.Fatalf("ScanHost error: %v", err)
	}

	if len(result.Ports) != 1 {
		t.Fatalf("expected 1 port result, got %d", len(result.Ports))
	}

	if result.Ports[0].Open {
		t.Errorf("port %d should be closed", port)
	}
	if result.Ports[0].State != PortClosed {
		t.Errorf("port %d state = %s, want closed", port, result.Ports[0].State)
	}
}

func TestScanHostMultiplePorts(t *testing.T) {
	// Start 3 listeners
	var openPorts []int
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("cannot start listener %d: %v", i, err)
		}
		defer ln.Close()
		openPorts = append(openPorts, ln.Addr().(*net.TCPAddr).Port)
		go func(l net.Listener) {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}(ln)
	}

	// Also add a closed port
	closedLn, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	closedLn.Close()

	allPorts := make([]int, len(openPorts)+1)
	copy(allPorts, openPorts)
	allPorts[len(openPorts)] = closedPort

	ctx := context.Background()
	result, err := ScanHost(ctx, "127.0.0.1", ScanOptions{
		Ports:   allPorts,
		Timeout: 2 * time.Second,
		Workers: 4,
	})
	if err != nil {
		t.Fatalf("ScanHost error: %v", err)
	}

	if len(result.Ports) != 4 {
		t.Fatalf("expected 4 port results, got %d", len(result.Ports))
	}

	openCount := 0
	for _, p := range result.Ports {
		if p.Open {
			openCount++
		}
	}
	if openCount != 3 {
		t.Errorf("expected 3 open ports, got %d", openCount)
	}
}

// --- Discovery Tests ---

func TestDiscoverHostsLocalhost(t *testing.T) {
	// Start a listener so connect discovery finds something
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port

	ctx := context.Background()
	results, err := DiscoverHosts(ctx, []string{"127.0.0.1"}, DiscoveryOptions{
		Methods: []DiscoveryMethod{DiscoveryConnect},
		Ports:   []int{port},
		Timeout: 2 * time.Second,
		Workers: 1,
	})
	if err != nil {
		t.Fatalf("DiscoverHosts error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Alive {
		t.Error("localhost should be alive")
	}
	if results[0].Latency <= 0 {
		t.Error("latency should be positive")
	}
}

func TestDiscoverHostsUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// RFC 5737 documentation address — should not be reachable
	results, err := DiscoverHosts(ctx, []string{"192.0.2.1"}, DiscoveryOptions{
		Methods: []DiscoveryMethod{DiscoveryConnect},
		Ports:   []int{80},
		Timeout: 500 * time.Millisecond,
		Workers: 1,
	})
	if err != nil {
		t.Fatalf("DiscoverHosts error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Alive {
		t.Skip("192.0.2.1 unexpectedly alive, skipping")
	}
}

func TestDiscoveryOptionsDefaults(t *testing.T) {
	opts := DiscoveryOptions{}
	opts.defaults()

	if len(opts.Methods) == 0 {
		t.Error("default methods should not be empty")
	}
	if len(opts.Ports) == 0 {
		t.Error("default ports should not be empty")
	}
	if opts.Timeout != 2*time.Second {
		t.Errorf("default timeout = %v, want 2s", opts.Timeout)
	}
	if opts.Workers != 100 {
		t.Errorf("default workers = %d, want 100", opts.Workers)
	}
}

// --- Progress Callback Tests ---

func TestScanHostProgress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	var mu sync.Mutex
	var progressCalls int
	var lastScanned, lastTotal int

	ctx := context.Background()
	_, err = ScanHost(ctx, "127.0.0.1", ScanOptions{
		Ports:   []int{ln.Addr().(*net.TCPAddr).Port, 1},
		Timeout: 1 * time.Second,
		Workers: 2,
		ProgressFunc: func(scanned, total int) {
			mu.Lock()
			defer mu.Unlock()
			progressCalls++
			lastScanned = scanned
			lastTotal = total
		},
	})
	if err != nil {
		t.Fatalf("ScanHost error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if progressCalls != 2 {
		t.Errorf("expected 2 progress calls, got %d", progressCalls)
	}
	if lastTotal != 2 {
		t.Errorf("expected total=2, got %d", lastTotal)
	}
	if lastScanned != 2 {
		t.Errorf("expected scanned=2, got %d", lastScanned)
	}
}

// --- Concurrency Safety Tests ---

func TestConcurrentScans(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := ScanHost(ctx, "127.0.0.1", ScanOptions{
				Ports:   []int{port},
				Timeout: 2 * time.Second,
				Workers: 1,
			})
			if err != nil {
				t.Errorf("concurrent ScanHost error: %v", err)
				return
			}
			if len(result.Ports) != 1 || !result.Ports[0].Open {
				t.Errorf("concurrent scan: port should be open")
			}
		}()
	}
	wg.Wait()
}

// --- Timeout Tests ---

func TestScanHostTimeout(t *testing.T) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Scan a non-routable IP — should timeout quickly due to context
	_, _ = ScanHost(ctx, "192.0.2.1", ScanOptions{
		Ports:   []int{80},
		Timeout: 500 * time.Millisecond,
		Workers: 1,
	})

	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Errorf("scan took too long: %v (expected < 5s)", elapsed)
	}
}

// --- Port Database Tests ---

func TestTopTCPPortsNotEmpty(t *testing.T) {
	if len(TopTCPPorts) == 0 {
		t.Error("TopTCPPorts should not be empty")
	}
	if len(TopTCPPorts) < 100 {
		t.Errorf("TopTCPPorts has %d entries, expected at least 100", len(TopTCPPorts))
	}
}

func TestCommonPortsMapPopulated(t *testing.T) {
	if len(CommonPorts) == 0 {
		t.Error("CommonPorts should not be empty")
	}
	// Should have same count as TopTCPPorts
	if len(CommonPorts) != len(TopTCPPorts) {
		t.Errorf("CommonPorts len = %d, TopTCPPorts len = %d, should match", len(CommonPorts), len(TopTCPPorts))
	}
}

func TestDetailedPortsNotEmpty(t *testing.T) {
	if len(DetailedPorts) == 0 {
		t.Error("DetailedPorts should not be empty")
	}
	if len(DetailedPorts) < 1000 {
		t.Errorf("DetailedPorts has %d entries, expected at least 1000", len(DetailedPorts))
	}
}

func TestTCPServicesHasCommonPorts(t *testing.T) {
	common := []int{22, 80, 443, 3306, 5432, 8080}
	for _, port := range common {
		if _, ok := TCPServices[port]; !ok {
			t.Errorf("TCPServices missing port %d", port)
		}
	}
}
