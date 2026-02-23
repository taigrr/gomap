# gomap

A pure Go, cross-platform, library-importable port scanner.

## Features

- **Cross-platform** — TCP connect scanning works on Linux, macOS, and Windows
- **Library-first** — import `github.com/taigrr/gomap` and scan from your own code
- **SYN stealth scanning** — available on Linux with raw socket privileges
- **ARP table parsing** — Linux only, via `/proc/net/arp`
- **Fast and full scan modes** — common ports (~75) or detailed list (~200+)
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

## License

0BSD
