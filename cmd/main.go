package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/taigrr/gomap"

	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"
)

var (
	fast     bool
	scanType string
	jsonOut  bool
	cidr     string
	topPorts int
	version  = "dev"
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

	if err := fang.Execute(context.Background(), rootCmd); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

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
