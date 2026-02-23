# gomap

A pure Go, cross-platform, library-importable port scanner.

## Features

- **Cross-platform** — TCP connect scanning works on Linux, macOS, and Windows
- **Library-first** — import `github.com/taigrr/gomap` and scan from your own code
- **SYN stealth scanning** — available on Linux with raw socket privileges
- **ARP table parsing** — Linux only, via `/proc/net/arp`
- **IANA service database** — 5,800+ TCP and 5,400+ UDP services from the official IANA registry
- **Top-ports scanning** — fast scan uses top 200 most commonly open ports
- **Full scan mode** — scans all IANA-registered ports
- **Context-aware** — all scans respect `context.Context` for cancellation
- **JSON output** — structured results for scripting

## Install

```bash
go install github.com/taigrr/gomap/cmd@latest
```

## CLI Usage

```bash
# Scan a single host (top ports)
gomap -f example.com

# Full scan (all known ports)
gomap example.com

# Scan a CIDR range
gomap -c 192.168.1.0/24 -f

# Top 100 ports only
gomap -t 100 example.com

# Different scan types (Linux, requires root)
sudo gomap -s syn example.com     # SYN stealth scan
sudo gomap -s fin example.com     # FIN scan
sudo gomap -s xmas example.com    # Xmas tree scan
sudo gomap -s null example.com    # Null scan
sudo gomap -s ack example.com     # ACK scan (firewall mapping)
sudo gomap -s window example.com  # Window scan
gomap -s udp example.com          # UDP scan

# Host discovery (ping sweep)
gomap -P -c 192.168.1.0/24

# OS detection
sudo gomap -O example.com

# Output formats
gomap -j example.com          # JSON
gomap -x example.com          # nmap-compatible XML
gomap -g example.com          # Grepable

# Service version detection (banner grabbing)
gomap -V example.com

# Timing templates
gomap -T aggressive example.com  # T4: fast
gomap -T insane example.com      # T5: maximum speed
gomap -T paranoid example.com    # T0: IDS evasion
```

## Library Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/taigrr/gomap"
)

func main() {
    ctx := context.Background()

    result, err := gomap.ScanHost(ctx, "example.com", gomap.ScanOptions{
        FastScan: true,
    })
    if err != nil {
        log.Fatal(err)
    }

    for _, p := range result.OpenPorts() {
        fmt.Printf("Port %d: %s\n", p.Port, p.Service)
    }
}
```

### Scan Options

```go
type ScanOptions struct {
    Protocol     string              // "tcp" (default)
    FastScan     bool                // Common ports only
    Stealth      bool                // SYN scan (Linux only)
    Timeout      time.Duration       // Per-port timeout (default 3s)
    Workers      int                 // Concurrent goroutines
    Ports        []int               // Custom port list (nil = use defaults)
    ProgressFunc func(scanned, total int) // Progress callback
}
```

### Scanning ranges

```go
// Scan a specific CIDR
results, err := gomap.ScanCIDR(ctx, "10.0.0.0/24", opts)

// Scan local network
results, err := gomap.ScanRange(ctx, opts)
```

### Utilities

```go
// Look up service name by port
svc := gomap.LookupService(443) // "HTTP protocol over TLS/SSL"

// Get local IP
ip, err := gomap.GetLocalIP()

// Get local /24 range
cidr := gomap.GetLocalRange()

// Parse CIDR to host list
hosts := gomap.CreateHostRange("192.168.1.0/24")

// MAC vendor lookup (37K OUI entries)
vendor := gomap.LookupMACVendor("00:50:56:12:34:56") // "VMware"

// Banner grabbing
sv, err := gomap.GrabBanner(ctx, "example.com", 22, 3*time.Second)
// sv.Service = "ssh", sv.Banner = "SSH-2.0-OpenSSH_9.0"

// Timing templates
gomap.ApplyTiming(&opts, gomap.TimingAggressive)
```

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| TCP connect scan | Yes | Yes | Yes |
| SYN stealth scan | Yes | No* | No* |
| FIN/Xmas/Null scan | Yes | No* | No* |
| ACK/Window scan | Yes | No* | No* |
| UDP scan | Yes | Yes | Yes |
| Host discovery (ICMP) | Yes | Yes** | Yes** |
| Host discovery (TCP) | Yes | Yes | Yes |
| ARP discovery | Yes | No | No |
| OS detection | Yes | No | No |

\* Falls back to connect scan on non-Linux platforms
\** May require elevated privileges

## Regenerating Service Data

The port-to-service mappings are generated from the IANA registry:

```bash
go generate ./...
```

This fetches the latest IANA CSV and regenerates `services_generated.go`.

## Roadmap

- [x] All TCP scan types (SYN, FIN, Xmas, Null, ACK, Window)
- [x] UDP scanning
- [x] Host discovery (ICMP, TCP SYN/ACK, UDP, ARP)
- [x] OS fingerprinting (TCP/IP stack analysis)
- [x] Service version detection (banner grabbing)
- [x] Timing templates (T0-T5)
- [x] XML output (nmap-compatible)
- [x] Grepable output (-oG)
- [x] MAC address vendor lookup (37K OUI entries)
- [ ] OS fingerprint database matching
- [ ] IPv6 support
- [ ] Traceroute
- [ ] NSE-style scripting

## License

0BSD
