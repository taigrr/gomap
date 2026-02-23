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
# Scan a single host (common ports)
gomap -f example.com

# Full scan
gomap example.com

# Scan a CIDR range
gomap -c 192.168.1.0/24 -f

# SYN stealth scan (Linux, requires root)
sudo gomap -s example.com

# JSON output
gomap -j example.com
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
```

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| TCP connect scan | Yes | Yes | Yes |
| SYN stealth scan | Yes | No | No |
| ARP table | Yes | No | No |

## Regenerating Service Data

The port-to-service mappings are generated from the IANA registry:

```bash
go generate ./...
```

This fetches the latest IANA CSV and regenerates `services_generated.go`.

## Roadmap

- [ ] UDP scanning
- [ ] Service version detection (banner grabbing)
- [ ] OS fingerprinting
- [ ] Additional scan types (FIN, XMAS, NULL, ACK, Window)
- [ ] Host discovery (ICMP, TCP/UDP ping)
- [ ] Timing templates (T0-T5)
- [ ] XML output (nmap-compatible)
- [ ] IPv6 support
- [ ] Traceroute
- [ ] MAC address vendor lookup

## License

0BSD
