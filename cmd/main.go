package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
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
	traceroute   bool
	preferIPv6   bool
	decoySpec    string
	scriptSpec   string
	scriptList   bool
	portSpec     string
	openOnly     bool
	reason       bool
	excludeHosts string
	scanDelay    time.Duration
	maxRetries   int
	hostTimeout  time.Duration
	noDNS        bool
	alwaysDNS    bool
	verbose      bool
	sourcePort   int
	outputNormal string
	outputXML    string
	outputGrep   string
	outputAll    string
	appendOutput bool
	noPing       bool
	inputFile    string
	excludeFile  string
	listScan     bool
	badSum       bool
	ttl          int
	dataLength       int
	minRate          int
	maxRate          int
	versionIntensity int
	packetTrace      bool
	osscanLimit      bool
	osscanGuess      bool
	version          = "dev"
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
	rootCmd.Flags().StringVarP(&scanType, "scan-type", "s", "connect", "Scan type: connect, syn, fin, xmas, null, ack, window, maimon, udp")
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
	rootCmd.Flags().StringVarP(&decoySpec, "decoys", "D", "", "Decoy IPs: RND,RND,ME,RND or ip1,ip2,ME")
	rootCmd.Flags().StringVar(&scriptSpec, "script", "", "Run scripts: default, safe, or script IDs (http-title,ssl-cert)")
	rootCmd.Flags().BoolVar(&scriptList, "script-list", false, "List available scripts and exit")
	rootCmd.Flags().StringVarP(&portSpec, "ports", "p", "", "Port specification: 80,443 or 1-1024 or T:80,U:53")
	rootCmd.Flags().BoolVar(&openOnly, "open", false, "Only show open ports")
	rootCmd.Flags().BoolVar(&reason, "reason", false, "Show the reason each port is in its state")
	rootCmd.Flags().StringVar(&excludeHosts, "exclude", "", "Comma-separated hosts/CIDRs to exclude")
	rootCmd.Flags().DurationVar(&scanDelay, "scan-delay", 0, "Minimum delay between probes (e.g. 100ms)")
	rootCmd.Flags().IntVar(&maxRetries, "max-retries", 0, "Maximum probe retransmissions")
	rootCmd.Flags().DurationVar(&hostTimeout, "host-timeout", 0, "Maximum time per host (e.g. 30s)")
	rootCmd.Flags().BoolVarP(&noDNS, "no-dns", "n", false, "Never do DNS resolution")
	rootCmd.Flags().BoolVarP(&alwaysDNS, "dns", "R", false, "Always resolve DNS")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().IntVar(&sourcePort, "source-port", 0, "Use given port number for scans")
	rootCmd.Flags().StringVar(&outputNormal, "oN", "", "Normal output to file")
	rootCmd.Flags().StringVar(&outputXML, "oX", "", "XML output to file")
	rootCmd.Flags().StringVar(&outputGrep, "oG", "", "Grepable output to file")
	rootCmd.Flags().StringVar(&outputAll, "oA", "", "Output in all formats (basename)")
	rootCmd.Flags().BoolVar(&appendOutput, "append-output", false, "Append to output files")
	rootCmd.Flags().BoolVar(&noPing, "Pn", false, "Skip host discovery, treat all hosts as online")
	rootCmd.Flags().StringVarP(&inputFile, "input-file", "i", "", "Read targets from file (one per line)")
	rootCmd.Flags().StringVar(&excludeFile, "excludefile", "", "Read exclude targets from file")
	rootCmd.Flags().BoolVar(&listScan, "list-scan", false, "List scan — resolve targets without scanning")
	rootCmd.Flags().BoolVar(&badSum, "badsum", false, "Send packets with bad checksums")
	rootCmd.Flags().IntVar(&ttl, "ttl", 0, "Set IP time-to-live on outgoing packets")
	rootCmd.Flags().IntVar(&dataLength, "data-length", 0, "Pad packets with random data to given length")
	rootCmd.Flags().IntVar(&minRate, "min-rate", 0, "Minimum packets per second")
	rootCmd.Flags().IntVar(&maxRate, "max-rate", 0, "Maximum packets per second")
	rootCmd.Flags().IntVar(&versionIntensity, "version-intensity", 7, "Service probe intensity (0-9)")
	rootCmd.Flags().BoolVar(&packetTrace, "packet-trace", false, "Log every packet sent/received")
	rootCmd.Flags().BoolVar(&osscanLimit, "osscan-limit", false, "Skip OS detection on hosts without open+closed ports")
	rootCmd.Flags().BoolVar(&osscanGuess, "osscan-guess", false, "Guess OS more aggressively")

	if err := fang.Execute(context.Background(), rootCmd); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	startTime := time.Now()

	// Load targets from file if specified
	if inputFile != "" {
		fileTargets, err := gomap.LoadTargetsFromFile(inputFile)
		if err != nil {
			return err
		}
		args = append(args, fileTargets...)
	}

	// Load excludes from file
	if excludeFile != "" {
		fileExcludes, err := gomap.LoadExcludesFromFile(excludeFile)
		if err != nil {
			return err
		}
		if excludeHosts != "" {
			excludeHosts += "," + strings.Join(fileExcludes, ",")
		} else {
			excludeHosts = strings.Join(fileExcludes, ",")
		}
	}

	// List scan mode
	if listScan {
		targets := args
		results, err := gomap.ListScan(targets, noDNS)
		if err != nil {
			return err
		}
		for _, r := range results {
			if r.Hostname != "" && r.Hostname != r.IP {
				fmt.Printf("%s (%s)\n", r.Hostname, r.IP)
			} else {
				fmt.Println(r.IP)
			}
		}
		fmt.Fprintf(os.Stderr, "%d targets listed\n", len(results))
		return nil
	}

	// Script list mode
	if scriptList {
		for _, id := range gomap.DefaultEngine.ListScripts() {
			s, _ := gomap.DefaultEngine.GetScript(id)
			fmt.Printf("%-20s %s\n", id, s.Description())
		}
		return nil
	}

	// Host discovery mode
	if discovery {
		return runDiscovery(ctx)
	}

	st, err := parseScanType(scanType)
	if err != nil {
		return err
	}

	opts := gomap.ScanOptions{
		FastScan:    fast,
		ScanType:    st,
		ProbeFile:   probeFile,
		PreferIPv6:  preferIPv6,
		OpenOnly:    openOnly,
		Reason:      reason,
		ScanDelay:   scanDelay,
		MaxRetries:  maxRetries,
		HostTimeout: hostTimeout,
		NoDNS:       noDNS,
		AlwaysDNS:   alwaysDNS,
		Verbose:     verbose,
		SourcePort:  sourcePort,
		NoPing:      noPing,
		BadSum:      badSum,
		TTL:         ttl,
		DataLength:       dataLength,
		MinRate:          minRate,
		MaxRate:          maxRate,
		VersionIntensity: versionIntensity,
		PacketTrace:      packetTrace,
		OSScanLimit:      osscanLimit,
		OSScanGuess:      osscanGuess,
	}

	// Parse port specification
	if portSpec != "" {
		ports, err := gomap.ParsePortRange(portSpec)
		if err != nil {
			return fmt.Errorf("parsing ports: %w", err)
		}
		opts.Ports = ports
	}

	// Parse exclude hosts
	if excludeHosts != "" {
		opts.ExcludeHosts = strings.Split(excludeHosts, ",")
	}

	// Configure file output
	outCfg := &gomap.OutputConfig{Append: appendOutput}
	if outputAll != "" {
		outCfg.NormalFile = outputAll + ".nmap"
		outCfg.XMLFile = outputAll + ".xml"
		outCfg.GrepFile = outputAll + ".gnmap"
	}
	if outputNormal != "" {
		outCfg.NormalFile = outputNormal
	}
	if outputXML != "" {
		outCfg.XMLFile = outputXML
	}
	if outputGrep != "" {
		outCfg.GrepFile = outputGrep
	}
	if outCfg.HasFileOutput() {
		opts.Output = outCfg
	}

	// Parse decoys
	if decoySpec != "" {
		laddr, err := gomap.GetLocalIP()
		if err != nil {
			return fmt.Errorf("getting local IP for decoys: %w", err)
		}
		dc, err := gomap.ParseDecoys(decoySpec, laddr)
		if err != nil {
			return fmt.Errorf("parsing decoys: %w", err)
		}
		opts.Decoys = dc
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
		return printResults(nil, results, st, startTime, opts)
	}

	if len(args) == 0 {
		results, err := gomap.ScanRange(ctx, opts)
		if err != nil {
			return err
		}
		clearProgress()
		return printResults(nil, results, st, startTime, opts)
	}

	result, err := gomap.ScanHost(ctx, args[0], opts)
	if err != nil {
		return err
	}
	clearProgress()

	if err := printResults(result, nil, st, startTime, opts); err != nil {
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
		} else if osscanLimit && closedPort == 0 {
			fmt.Fprintln(os.Stderr, "OS detection skipped (--osscan-limit: no closed port found)")
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

	// Script execution
	if scriptSpec != "" && result != nil && len(args) > 0 {
		var scripts []gomap.Script
		switch scriptSpec {
		case "default":
			scripts = gomap.DefaultEngine.SelectByCategory(gomap.CategoryDefault)
		case "safe":
			scripts = gomap.DefaultEngine.SelectByCategory(gomap.CategorySafe)
		case "all":
			scripts = gomap.DefaultEngine.SelectByIDs("*")
		default:
			ids := strings.Split(scriptSpec, ",")
			scripts = gomap.DefaultEngine.SelectByIDs(ids...)
		}

		if len(scripts) > 0 {
			if !jsonOut && !xmlOut && !grepOut {
				fmt.Println("\nScript Results:")
			}
			for _, p := range result.Ports {
				if !p.Open {
					continue
				}
				target := gomap.ScriptTarget{
					Host:    args[0],
					Port:    p.Port,
					Service: p.Service,
					Result:  result,
				}
				outputs := gomap.DefaultEngine.RunScripts(ctx, scripts, target, 4)
				for _, out := range outputs {
					if !jsonOut && !xmlOut && !grepOut {
						fmt.Printf("  %d/%s:\n    %s\n", p.Port, p.Service, out.String())
					}
				}
			}
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
	case "maimon":
		return gomap.MaimonScan, nil
	case "udp":
		return gomap.UDPScan, nil
	default:
		return gomap.ConnectScan, fmt.Errorf("unknown scan type: %s (valid: connect, syn, fin, xmas, null, ack, window, maimon, udp)", s)
	}
}

func clearProgress() {
	if !jsonOut && !xmlOut && !grepOut {
		fmt.Fprintln(os.Stderr)
	}
}

func printResults(single *gomap.ScanResult, multi gomap.RangeScanResult, st gomap.ScanType, startTime time.Time, opts gomap.ScanOptions) error {
	// Generate all output formats needed
	var normalOut, grepableOut string
	var xmlData []byte

	if single != nil {
		normalOut = single.String()
		grepableOut = single.ToGrepable()
		var err error
		xmlData, err = single.ToXML(st, startTime, version)
		if err != nil {
			return err
		}
	} else {
		normalOut = multi.String()
		grepableOut = multi.ToGrepable()
		var err error
		xmlData, err = multi.ToXML(st, startTime, version)
		if err != nil {
			return err
		}
	}

	// Add reason column to normal output if requested
	if opts.Reason && !jsonOut && !xmlOut && !grepOut {
		normalOut = addReasonToOutput(single, multi)
	}

	// Print to stdout
	switch {
	case xmlOut:
		fmt.Println(string(xmlData))
	case grepOut:
		fmt.Print(grepableOut)
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
		fmt.Print(normalOut)
	}

	// Write to files
	if opts.Output != nil {
		return opts.Output.WriteAll(normalOut, xmlData, grepableOut)
	}

	return nil
}

func addReasonToOutput(single *gomap.ScanResult, multi gomap.RangeScanResult) string {
	var results []*gomap.ScanResult
	if single != nil {
		results = []*gomap.ScanResult{single}
	} else {
		results = multi
	}

	var b strings.Builder
	for _, r := range results {
		fmt.Fprintf(&b, "Scan report for %s\n", r.Hostname)
		fmt.Fprintf(&b, "%-10s %-12s %-15s %s\n", "PORT", "STATE", "SERVICE", "REASON")
		for _, p := range r.Ports {
			reasonStr := p.Reason
			if reasonStr == "" {
				reasonStr = "unknown"
			}
			fmt.Fprintf(&b, "%-10s %-12s %-15s %s\n",
				fmt.Sprintf("%d/tcp", p.Port),
				p.State.String(),
				p.Service,
				reasonStr,
			)
		}
		b.WriteString("\n")
	}
	return b.String()
}
