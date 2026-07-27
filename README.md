# gomap

[![CI](https://github.com/taigrr/gomap/actions/workflows/ci.yml/badge.svg)](https://github.com/taigrr/gomap/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/taigrr/gomap.svg)](https://pkg.go.dev/github.com/taigrr/gomap)
[![Go Report Card](https://goreportcard.com/badge/github.com/taigrr/gomap)](https://goreportcard.com/report/github.com/taigrr/gomap)
[![License: 0BSD](https://img.shields.io/badge/License-0BSD-blue.svg)](LICENSE)

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
go install github.com/taigrr/gomap/cmd/gomap@latest
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
opts := gomap.ScanOptions{
    ScanType:         gomap.ConnectScan, // SYNScan, FINScan, UDPScan, etc.
    FastScan:         true,              // Common ports only
    Timeout:          3 * time.Second,   // Per-port timeout
    Workers:          500,               // Concurrent goroutines
    Ports:            []int{80, 443},    // Custom port list (nil = defaults)
    OpenOnly:         true,              // Filter to open ports only
    VersionIntensity: 7,                 // Service probe depth (0-9)
    ProgressFunc:     func(scanned, total int) { /* ... */ },
}
```

See the `ScanOptions` struct in the [GoDoc](https://pkg.go.dev/github.com/taigrr/gomap) for the full list of options including timing, rate limiting, proxies, decoys, and more.

### Scanning ranges

```go
// Scan a specific CIDR
results, err := gomap.ScanCIDR(ctx, "10.0.0.0/24", opts)

// Scan local network
results, err := gomap.ScanRange(ctx, opts)
```

### Streaming API

For UIs and interactive applications that want results as they arrive:

```go
events := gomap.ScanHostStream(ctx, "example.com", opts)
for ev := range events {
    if ev.Port != nil && ev.Port.Open {
        fmt.Printf("Found open port: %d\n", ev.Port.Port)
    }
    if ev.Done {
        fmt.Println("Scan complete")
    }
}
```

### Host Discovery

```go
hosts := gomap.CreateHostRange("192.168.1.0/24")
results, err := gomap.DiscoverHosts(ctx, hosts, gomap.DiscoveryOptions{
    Methods: []gomap.DiscoveryMethod{gomap.DiscoveryICMP, gomap.DiscoveryConnect},
    Timeout: 2 * time.Second,
})
for _, r := range results {
    if r.Alive {
        fmt.Printf("%s is up (%s)\n", r.IP, r.Latency)
    }
}
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

// Banner grabbing (nil uses embedded probe DB)
sv, err := gomap.GrabBanner(ctx, "example.com", 22, 3*time.Second, nil)
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

## nmap Database Compatibility

gomap can parse and use nmap's database files directly:

```go
import "github.com/taigrr/gomap/probedb"

// Load from files at runtime
db, _ := probedb.LoadServiceProbesFile("/usr/share/nmap/nmap-service-probes")
osdb, _ := probedb.LoadOSDBFile("/usr/share/nmap/nmap-os-db")

// Or embed at compile time with go:embed
//go:embed nmap-service-probes
var serviceProbesData []byte

db, _ := probedb.LoadServiceProbesData(serviceProbesData)

// Or from fs.FS
//go:embed data
var dbFS embed.FS

db, _ := probedb.LoadServiceProbesFS(dbFS, "data/nmap-service-probes")

// Auto-find installed nmap databases
spPath, osPath := probedb.FindDatabases()
```

Supported database formats:
- **nmap-service-probes** — 187 probes, 11,266 match patterns for service/version detection
- **nmap-os-db** — 6,036 OS fingerprints with scoring/matching
- **nmap-mac-prefixes** — MAC vendor OUI lookup (via generate-mac tool)
- **nmap-services** — Port-to-service mappings (via generate-services tool)

Set `GOMAP_DB_PATH` to specify a custom database directory.

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
- [x] OS fingerprint database matching (nmap-os-db)
- [x] Traceroute (UDP-based)
- [x] NSE-style scripting engine (http-title, ssh-hostkey, ssl-cert, smtp-commands, ftp-anon, mysql-info, redis-info)
- [ ] IPv6 scanning support

## License

0BSD
