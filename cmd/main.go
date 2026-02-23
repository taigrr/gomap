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
	fast       bool
	scanType   string
	jsonOut    bool
	xmlOut     bool
	grepOut    bool
	cidr       string
	topPorts   int
	discovery  bool
	osDetect   bool
	bannerGrab bool
	timing     string
	probeFile  string
	traceroute bool
	preferIPv6 bool
	version    = "dev"
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
	rootCmd.Flags().BoolVarP(&xmlOut, "xml", "x", false, "Output as nmap-compatible XML")
	rootCmd.Flags().BoolVarP(&grepOut, "grep", "g", false, "Output in grepable format")
	rootCmd.Flags().StringVarP(&cidr, "cidr", "c", "", "Scan a CIDR range instead of a single host")
	rootCmd.Flags().IntVarP(&topPorts, "top-ports", "t", 0, "Scan only the top N most common ports")
	rootCmd.Flags().BoolVarP(&discovery, "ping", "P", false, "Host discovery only (no port scan)")
	rootCmd.Flags().BoolVarP(&osDetect, "os", "O", false, "Enable OS detection (requires root)")
	rootCmd.Flags().BoolVarP(&bannerGrab, "version", "V", false, "Enable service version detection (banner grabbing)")
	rootCmd.Flags().StringVarP(&timing, "timing", "T", "", "Timing template: T0-T5 or paranoid/sneaky/polite/normal/aggressive/insane")
	rootCmd.Flags().StringVar(&probeFile, "service-probes", "", "Path to nmap-service-probes file (default: embedded database)")
	rootCmd.Flags().BoolVar(&traceroute, "traceroute", false, "Trace the route to the host")
	rootCmd.Flags().BoolVarP(&preferIPv6, "ipv6", "6", false, "Prefer IPv6 addresses")

	if err := fang.Execute(context.Background(), rootCmd); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	startTime := time.Now()

	// Host discovery mode
	if discovery {
		return runDiscovery(ctx)
	}

	st, err := parseScanType(scanType)
	if err != nil {
		return err
	}

	opts := gomap.ScanOptions{
		FastScan:  fast,
		ScanType:  st,
		ProbeFile:  probeFile,
		PreferIPv6: preferIPv6,
	}

	// Apply timing template
	if timing != "" {
		tt, err := gomap.ParseTimingTemplate(timing)
		if err != nil {
			return err
		}
		gomap.ApplyTiming(&opts, tt)
	}

	// Progress (only for non-machine-readable output)
	if !jsonOut && !xmlOut && !grepOut {
		opts.ProgressFunc = func(scanned, total int) {
			fmt.Fprintf(os.Stderr, "\033[2K\rScanning: %d/%d ports", scanned, total)
		}
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
		return printResults(nil, results, st, startTime)
	}

	if len(args) == 0 {
		results, err := gomap.ScanRange(ctx, opts)
		if err != nil {
			return err
		}
		clearProgress()
		return printResults(nil, results, st, startTime)
	}

	result, err := gomap.ScanHost(ctx, args[0], opts)
	if err != nil {
		return err
	}
	clearProgress()

	if err := printResults(result, nil, st, startTime); err != nil {
		return err
	}

	// Banner grabbing
	if bannerGrab && result != nil && len(args) > 0 {
		versions := gomap.GrabBanners(ctx, args[0], result, opts)
		if len(versions) > 0 && !jsonOut && !xmlOut && !grepOut {
			fmt.Println("\nService Versions:")
			for _, v := range versions {
				svc := v.Service
				if v.ProductName != "" {
					svc = v.ProductName
				}
				if v.Version != "" {
					svc += " " + v.Version
				}
				fmt.Printf("  %d/%s: %s\n", v.Port, svc, v.Banner)
			}
		}
	}

	// OS detection
	if osDetect && result != nil && len(args) > 0 {
		openPort, closedPort := findOSDetectPorts(result)
		if openPort == 0 {
			fmt.Fprintln(os.Stderr, "OS detection requires at least one open port")
		} else {
			osResult, err := gomap.DetectOS(ctx, args[0], openPort, closedPort, opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "OS detection failed: %v\n", err)
			} else if !xmlOut {
				if len(osResult.Matches) > 0 {
					fmt.Println("\nOS Detection:")
					for i, m := range osResult.Matches {
						if i >= 5 {
							break
						}
						fmt.Printf("  %s (%.0f%% accuracy)", m.Name, m.Accuracy*100)
						if m.Family != "" {
							fmt.Printf(" [%s", m.Family)
							if m.Generation != "" {
								fmt.Printf(" %s", m.Generation)
							}
							fmt.Print("]")
						}
						fmt.Println()
					}
				} else {
					fmt.Println("\nOS Fingerprint (no DB match):")
					fmt.Print(osResult.Raw)
				}
			}
		}
	}

	// Traceroute
	if traceroute && len(args) > 0 {
		trOpts := gomap.TracerouteOptions{
			Timeout: 2 * time.Second,
			Port:    80,
		}
		if timing != "" {
			tt, _ := gomap.ParseTimingTemplate(timing)
			if tt <= gomap.TimingPolite {
				trOpts.Timeout = 5 * time.Second
			}
		}
		tr, err := gomap.Traceroute(ctx, args[0], trOpts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Traceroute failed: %v\n", err)
		} else if !xmlOut && !grepOut {
			fmt.Println()
			fmt.Print(tr.String())
		}
	}

	return nil
}

func runDiscovery(ctx context.Context) error {
	opts := gomap.DiscoveryOptions{}

	if timing != "" {
		tt, err := gomap.ParseTimingTemplate(timing)
		if err != nil {
			return err
		}
		gomap.ApplyTimingDiscovery(&opts, tt)
	}

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

func findOSDetectPorts(result *gomap.ScanResult) (openPort, closedPort int) {
	for _, p := range result.Ports {
		if p.Open && openPort == 0 {
			openPort = p.Port
		}
		if !p.Open && closedPort == 0 {
			closedPort = p.Port
		}
		if openPort != 0 && closedPort != 0 {
			break
		}
	}
	return
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

func clearProgress() {
	if !jsonOut && !xmlOut && !grepOut {
		fmt.Fprintln(os.Stderr)
	}
}

func printResults(single *gomap.ScanResult, multi gomap.RangeScanResult, st gomap.ScanType, startTime time.Time) error {
	switch {
	case xmlOut:
		var data []byte
		var err error
		if single != nil {
			data, err = single.ToXML(st, startTime, version)
		} else {
			data, err = multi.ToXML(st, startTime, version)
		}
		if err != nil {
			return err
		}
		fmt.Println(string(data))

	case grepOut:
		if single != nil {
			fmt.Print(single.ToGrepable())
		} else {
			fmt.Print(multi.ToGrepable())
		}

	case jsonOut:
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

	default:
		if single != nil {
			fmt.Print(single.String())
		} else {
			fmt.Print(multi.String())
		}
	}

	return nil
}
