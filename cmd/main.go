package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/taigrr/gomap"

	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"
)

var (
	fast      bool
	scanType  string
	jsonOut   bool
	cidr      string
	topPorts  int
	discovery bool
	version   = "dev"
)

func main() {
	rootCmd := &cobra.Command{
		Use:          "gomap [hostname]",
		Short:        "A pure Go port scanner",
		Long:         "gomap is a cross-platform, library-importable port scanner written in pure Go.",
		Version:      version,
		Args:         cobra.MaximumNArgs(1),
		RunE:         run,
		SilenceUsage: true,
	}

	rootCmd.Flags().BoolVarP(&fast, "fast", "f", false, "Fast scan (top ports only)")
	rootCmd.Flags().StringVarP(&scanType, "scan-type", "s", "connect", "Scan type: connect, syn, fin, xmas, null, ack, window, udp")
	rootCmd.Flags().BoolVarP(&jsonOut, "json", "j", false, "Output as JSON")
	rootCmd.Flags().StringVarP(&cidr, "cidr", "c", "", "Scan a CIDR range instead of a single host")
	rootCmd.Flags().IntVarP(&topPorts, "top-ports", "t", 0, "Scan only the top N most common ports")
	rootCmd.Flags().BoolVarP(&discovery, "ping", "P", false, "Host discovery only (no port scan)")

	if err := fang.Execute(context.Background(), rootCmd); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Host discovery mode
	if discovery {
		return runDiscovery(ctx)
	}

	st, err := parseScanType(scanType)
	if err != nil {
		return err
	}

	opts := gomap.ScanOptions{
		FastScan: fast,
		ScanType: st,
		ProgressFunc: func(scanned, total int) {
			if !jsonOut {
				fmt.Fprintf(os.Stderr, "\033[2K\rScanning: %d/%d ports", scanned, total)
			}
		},
	}

	// --top-ports overrides --fast
	if topPorts > 0 {
		if topPorts > len(gomap.TopTCPPorts) {
			topPorts = len(gomap.TopTCPPorts)
		}
		opts.Ports = gomap.TopTCPPorts[:topPorts]
	}

	if cidr != "" {
		results, err := gomap.ScanCIDR(ctx, cidr, opts)
		if err != nil {
			return err
		}
		clearProgress()
		return printResults(nil, results)
	}

	if len(args) == 0 {
		results, err := gomap.ScanRange(ctx, opts)
		if err != nil {
			return err
		}
		clearProgress()
		return printResults(nil, results)
	}

	result, err := gomap.ScanHost(ctx, args[0], opts)
	if err != nil {
		return err
	}
	clearProgress()
	return printResults(result, nil)
}

func clearProgress() {
	if !jsonOut {
		fmt.Fprintln(os.Stderr)
	}
}

func runDiscovery(ctx context.Context) error {
	opts := gomap.DiscoveryOptions{}
	var results []gomap.HostResult
	var err error

	if cidr != "" {
		results, err = gomap.DiscoverCIDR(ctx, cidr, opts)
	} else {
		results, err = gomap.DiscoverLocal(ctx, opts)
	}
	if err != nil {
		return err
	}

	alive := 0
	for _, r := range results {
		if r.Alive {
			alive++
			name := r.IP
			if r.Hostname != "" {
				name = fmt.Sprintf("%s (%s)", r.Hostname, r.IP)
			}
			if jsonOut {
				fmt.Printf("{\"ip\":%q,\"hostname\":%q,\"alive\":true,\"latency\":%q}\n", r.IP, r.Hostname, r.Latency)
			} else {
				fmt.Printf("Host %s is up (latency: %s)\n", name, r.Latency.Round(time.Millisecond))
			}
		}
	}

	if !jsonOut {
		fmt.Fprintf(os.Stderr, "\n%d hosts up out of %d scanned\n", alive, len(results))
	}
	return nil
}

func parseScanType(s string) (gomap.ScanType, error) {
	switch s {
	case "connect", "tcp", "":
		return gomap.ConnectScan, nil
	case "syn", "stealth":
		return gomap.SYNScan, nil
	case "fin":
		return gomap.FINScan, nil
	case "xmas":
		return gomap.XmasScan, nil
	case "null":
		return gomap.NullScan, nil
	case "ack":
		return gomap.ACKScan, nil
	case "window":
		return gomap.WindowScan, nil
	case "udp":
		return gomap.UDPScan, nil
	default:
		return gomap.ConnectScan, fmt.Errorf("unknown scan type: %s (valid: connect, syn, fin, xmas, null, ack, window, udp)", s)
	}
}

func printResults(single *gomap.ScanResult, multi gomap.RangeScanResult) error {
	if jsonOut {
		var out string
		var err error
		if single != nil {
			out, err = single.JSON()
		} else {
			out, err = multi.JSON()
		}
		if err != nil {
			return err
		}
		fmt.Println(out)
		return nil
	}

	if single != nil {
		fmt.Print(single.String())
	} else {
		fmt.Print(multi.String())
	}
	return nil
}
