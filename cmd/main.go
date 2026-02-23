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
	fast    bool
	stealth bool
	json    bool
	cidr    string
	version = "dev"
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "gomap [hostname]",
		Short:   "A pure Go port scanner",
		Long:    "gomap is a cross-platform, library-importable port scanner written in pure Go.",
		Version: version,
		Args:    cobra.MaximumNArgs(1),
		RunE:    run,
	}

	rootCmd.Flags().BoolVarP(&fast, "fast", "f", false, "Fast scan (common ports only)")
	rootCmd.Flags().BoolVarP(&stealth, "stealth", "s", false, "SYN stealth scan (Linux only, requires root)")
	rootCmd.Flags().BoolVarP(&json, "json", "j", false, "Output as JSON")
	rootCmd.Flags().StringVarP(&cidr, "cidr", "c", "", "Scan a CIDR range instead of a single host")

	if err := fang.Execute(context.Background(), rootCmd); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	opts := gomap.ScanOptions{
		FastScan: fast,
		Stealth:  stealth,
		ProgressFunc: func(scanned, total int) {
			if !json {
				fmt.Fprintf(os.Stderr, "\033[2K\rScanning: %d/%d ports", scanned, total)
			}
		},
	}

	if cidr != "" {
		results, err := gomap.ScanCIDR(ctx, cidr, opts)
		if err != nil {
			return err
		}
		if !json {
			fmt.Fprintln(os.Stderr) // newline after progress
		}
		return printResults(nil, results)
	}

	if len(args) == 0 {
		// No host specified, scan local range
		results, err := gomap.ScanRange(ctx, opts)
		if err != nil {
			return err
		}
		if !json {
			fmt.Fprintln(os.Stderr)
		}
		return printResults(nil, results)
	}

	result, err := gomap.ScanHost(ctx, args[0], opts)
	if err != nil {
		return err
	}
	if !json {
		fmt.Fprintln(os.Stderr)
	}
	return printResults(result, nil)
}

func printResults(single *gomap.ScanResult, multi gomap.RangeScanResult) error {
	if json {
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
