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
	fast             bool
	scanType         string
	jsonOut          bool
	xmlOut           bool
	grepOut          bool
	cidr             string
	topPorts         int
	discovery        bool
	osDetect         bool
	bannerGrab       bool
	timing           string
	probeFile        string
	traceroute       bool
	preferIPv6       bool
	decoySpec        string
	scriptSpec       string
	scriptList       bool
	portSpec         string
	openOnly         bool
	reason           bool
	excludeHosts     string
	scanDelay        time.Duration
	maxRetries       int
	hostTimeout      time.Duration
	noDNS            bool
	alwaysDNS        bool
	verbose          bool
	sourcePort       int
	outputNormal     string
	outputXML        string
	outputGrep       string
	outputAll        string
	appendOutput     bool
	noPing           bool
	inputFile        string
	excludeFile      string
	listScan         bool
	badSum           bool
	ttl              int
	dataLength       int
	minRate          int
	maxRate          int
	versionIntensity int
	packetTrace      bool
	osscanLimit      bool
	osscanGuess      bool
	fragment         bool
	mtu              int
	spoofMAC         string
	zombieHost       string
	ftpBounce        string
	randomTargets    int
	dnsServers       string
	minParallelism   int
	maxParallelism   int
	minRTTTimeout    time.Duration
	maxRTTTimeout    time.Duration
	initialRTT       time.Duration
	resumeFile       string
	scanFlags        string
	spoofSource      string
	proxies          string
	dataHex          string
	dataString       string
	ipOptions        string
	maxOSTries       int
	versionTrace     bool
	scriptArgs       string
	scriptTrace      bool
	excludePorts     string
	minHostgroup     int
	maxHostgroup     int
	outputSkiddie    string
	ifList           bool
	stylesheet       string
	webXML           bool
	noStylesheet     bool
	portRatio        float64
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

	rootCmd.Flags().BoolVarP(&fast, "fast", "F", false, "Fast scan (top ports only)")
	rootCmd.Flags().StringVarP(&scanType, "scan-type", "s", "connect", "Scan type: connect, syn, fin, xmas, null, ack, window, maimon, udp, sctp-init, sctp-cookie-echo, idle, ftp-bounce")
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
	rootCmd.Flags().BoolVarP(&fragment, "fragment", "f", false, "Fragment IP packets")
	rootCmd.Flags().IntVar(&mtu, "mtu", 0, "Set MTU for fragmentation (implies -f)")
	rootCmd.Flags().StringVar(&spoofMAC, "spoof-mac", "", "Spoof MAC address (addr, vendor, or 0 for random)")
	rootCmd.Flags().StringVar(&zombieHost, "idle-zombie", "", "Zombie host for idle scan (-sI)")
	rootCmd.Flags().StringVar(&ftpBounce, "ftp-bounce", "", "FTP server for bounce scan (-b host:port)")
	rootCmd.Flags().IntVar(&randomTargets, "random-targets", 0, "Generate N random targets (-iR)")
	rootCmd.Flags().StringVar(&dnsServers, "dns-servers", "", "Custom DNS servers (comma-separated)")
	rootCmd.Flags().IntVar(&minParallelism, "min-parallelism", 0, "Minimum parallel probes")
	rootCmd.Flags().IntVar(&maxParallelism, "max-parallelism", 0, "Maximum parallel probes")
	rootCmd.Flags().DurationVar(&minRTTTimeout, "min-rtt-timeout", 0, "Minimum RTT timeout")
	rootCmd.Flags().DurationVar(&maxRTTTimeout, "max-rtt-timeout", 0, "Maximum RTT timeout")
	rootCmd.Flags().DurationVar(&initialRTT, "initial-rtt-timeout", 0, "Initial RTT timeout")
	rootCmd.Flags().StringVar(&resumeFile, "resume", "", "Resume scan from file")
	rootCmd.Flags().StringVar(&scanFlags, "scanflags", "", "Custom TCP scan flags (e.g., URGACKPSHRSTSYNFIN, 0x29)")
	rootCmd.Flags().StringVarP(&spoofSource, "spoof-source", "S", "", "Spoof source IP address")
	rootCmd.Flags().StringVar(&proxies, "proxies", "", "Relay connections through HTTP/SOCKS4 proxies (comma-separated URLs)")
	rootCmd.Flags().StringVar(&dataHex, "data", "", "Append custom hex payload to packets")
	rootCmd.Flags().StringVar(&dataString, "data-string", "", "Append custom ASCII string to packets")
	rootCmd.Flags().StringVar(&ipOptions, "ip-options", "", "Send packets with specified IP options (hex)")
	rootCmd.Flags().IntVar(&maxOSTries, "max-os-tries", 0, "Maximum number of OS detection attempts")
	rootCmd.Flags().BoolVar(&versionTrace, "version-trace", false, "Show detailed version scan activity")
	rootCmd.Flags().StringVar(&scriptArgs, "script-args", "", "Arguments to scripts (key1=val1,key2=val2)")
	rootCmd.Flags().BoolVar(&scriptTrace, "script-trace", false, "Show all script data sent/received")
	rootCmd.Flags().StringVar(&excludePorts, "exclude-ports", "", "Exclude specified ports from scanning")
	rootCmd.Flags().IntVar(&minHostgroup, "min-hostgroup", 0, "Minimum parallel host scan group size")
	rootCmd.Flags().IntVar(&maxHostgroup, "max-hostgroup", 0, "Maximum parallel host scan group size")
	rootCmd.Flags().StringVar(&outputSkiddie, "oS", "", "Script kiddie output to file")
	rootCmd.Flags().BoolVar(&ifList, "iflist", false, "Print host interfaces and routes")
	rootCmd.Flags().StringVar(&stylesheet, "stylesheet", "", "XSL stylesheet for XML output")
	rootCmd.Flags().BoolVar(&webXML, "webxml", false, "Reference Nmap.Org stylesheet for portable XML")
	rootCmd.Flags().BoolVar(&noStylesheet, "no-stylesheet", false, "Prevent XSL stylesheet in XML output")
	rootCmd.Flags().Float64Var(&portRatio, "port-ratio", 0, "Scan ports with open frequency >= ratio (0.0-1.0)")

	if err := fang.Execute(context.Background(), rootCmd); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	startTime := time.Now()

	// Generate random targets
	if randomTargets > 0 {
		args = append(args, gomap.GenerateRandomTargets(randomTargets)...)
	}

	// Resume scan
	if resumeFile != "" {
		state, err := gomap.LoadResume(resumeFile)
		if err != nil {
			return fmt.Errorf("loading resume file: %w", err)
		}
		remaining := state.RemainingTargets()
		if len(remaining) == 0 {
			fmt.Println("All targets already completed.")
			return nil
		}
		args = append(args, remaining...)
		fmt.Fprintf(os.Stderr, "Resuming scan: %d/%d targets remaining\n", len(remaining), len(state.Targets))
	}

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
		FastScan:          fast,
		ScanType:          st,
		ProbeFile:         probeFile,
		PreferIPv6:        preferIPv6,
		OpenOnly:          openOnly,
		Reason:            reason,
		ScanDelay:         scanDelay,
		MaxRetries:        maxRetries,
		HostTimeout:       hostTimeout,
		NoDNS:             noDNS,
		AlwaysDNS:         alwaysDNS,
		Verbose:           verbose,
		SourcePort:        sourcePort,
		NoPing:            noPing,
		BadSum:            badSum,
		TTL:               ttl,
		DataLength:        dataLength,
		MinRate:           minRate,
		MaxRate:           maxRate,
		VersionIntensity:  versionIntensity,
		PacketTrace:       packetTrace,
		OSScanLimit:       osscanLimit,
		OSScanGuess:       osscanGuess,
		Fragment:          fragment || mtu > 0,
		MTU:               mtu,
		SpoofMAC:          spoofMAC,
		MinParallelism:    minParallelism,
		MaxParallelism:    maxParallelism,
		MinRTTTimeout:     minRTTTimeout,
		MaxRTTTimeout:     maxRTTTimeout,
		InitialRTTTimeout: initialRTT,
		SpoofSourceIP:     spoofSource,
		DataString:        dataString,
		MaxOSTries:        maxOSTries,
		VersionTrace:      versionTrace,
		ScriptTrace:       scriptTrace,
		MinHostgroup:      minHostgroup,
		MaxHostgroup:      maxHostgroup,
	}

	// --iflist: print interfaces and exit
	if ifList {
		ifaces, err := gomap.ListInterfaces()
		if err != nil {
			return err
		}
		fmt.Print(gomap.FormatInterfaceList(ifaces))
		return nil
	}

	// IP protocol scan mode (-sO)
	if scanType == "protocol" || scanType == "ip-proto" || scanType == "sO" {
		if len(args) == 0 {
			return fmt.Errorf("IP protocol scan requires a target host")
		}
		results, err := gomap.IPProtocolScan(ctx, args[0], opts)
		if err != nil {
			return err
		}
		for _, r := range results {
			if r.Open {
				fmt.Printf("%-6d %-18s %s\n", r.Protocol, r.State.String(), r.Name)
			}
		}
		return nil
	}

	// Parse --scanflags
	if scanFlags != "" {
		flags, err := gomap.ParseScanFlags(scanFlags)
		if err != nil {
			return fmt.Errorf("parsing scanflags: %w", err)
		}
		opts.ScanFlags = flags
		opts.ScanFlagsSet = true
	}

	// Parse --proxies
	if proxies != "" {
		opts.Proxies = strings.Split(proxies, ",")
	}

	// Parse --data (hex)
	if dataHex != "" {
		data, err := parseHexData(dataHex)
		if err != nil {
			return fmt.Errorf("parsing --data: %w", err)
		}
		opts.Data = data
	}

	// Parse --ip-options (hex)
	if ipOptions != "" {
		data, err := parseHexData(ipOptions)
		if err != nil {
			return fmt.Errorf("parsing --ip-options: %w", err)
		}
		opts.IPOptions = data
	}

	// Parse --script-args
	if scriptArgs != "" {
		opts.ScriptArgs = parseScriptArgs(scriptArgs)
	}

	// Parse --exclude-ports
	if excludePorts != "" {
		excluded, err := gomap.ParsePortRange(excludePorts)
		if err != nil {
			return fmt.Errorf("parsing --exclude-ports: %w", err)
		}
		opts.ExcludePorts = excluded
	}

	// --port-ratio overrides --top-ports and port spec
	if portRatio > 0 {
		opts.Ports = gomap.PortsByRatio(portRatio)
	}

	// Parse port specification
	if portSpec != "" && portRatio == 0 {
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
	if outputSkiddie != "" {
		outCfg.ScriptKiddieFile = outputSkiddie
	}
	if outCfg.HasFileOutput() {
		opts.Output = outCfg
	}

	// Configure idle scan zombie
	if zombieHost != "" {
		opts.IdleZombie = gomap.IdleScanConfig{ZombieHost: zombieHost}
		if opts.ScanType != gomap.IdleScan {
			opts.ScanType = gomap.IdleScan
		}
	}

	// Configure FTP bounce
	if ftpBounce != "" {
		opts.FTPBounce = gomap.FTPBounceConfig{Server: ftpBounce}
		if opts.ScanType != gomap.FTPBounceScan {
			opts.ScanType = gomap.FTPBounceScan
		}
	}

	// DNS servers
	if dnsServers != "" {
		opts.DNSServers = strings.Split(dnsServers, ",")
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
					Args:    opts.ScriptArgs,
					Trace:   opts.ScriptTrace,
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
	case "sctp-init", "sctp", "sY":
		return gomap.SCTPInitScan, nil
	case "sctp-cookie-echo", "sZ":
		return gomap.SCTPCookieEchoScan, nil
	case "idle":
		return gomap.IdleScan, nil
	case "ftp-bounce", "bounce":
		return gomap.FTPBounceScan, nil
	case "protocol", "ip-proto", "sO":
		return gomap.ConnectScan, nil // protocol scan handled separately
	default:
		return gomap.ConnectScan, fmt.Errorf("unknown scan type: %s (valid: connect, syn, fin, xmas, null, ack, window, maimon, udp, sctp-init, sctp-cookie-echo, idle, ftp-bounce)", s)
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

func parseHexData(hex string) ([]byte, error) {
	hex = strings.TrimPrefix(hex, "0x")
	hex = strings.TrimPrefix(hex, "0X")
	hex = strings.ReplaceAll(hex, " ", "")
	hex = strings.ReplaceAll(hex, ":", "")
	if len(hex)%2 != 0 {
		hex = "0" + hex
	}
	data := make([]byte, len(hex)/2)
	for i := 0; i < len(hex); i += 2 {
		var b byte
		for j := 0; j < 2; j++ {
			c := hex[i+j]
			switch {
			case c >= '0' && c <= '9':
				b = (b << 4) | (c - '0')
			case c >= 'a' && c <= 'f':
				b = (b << 4) | (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				b = (b << 4) | (c - 'A' + 10)
			default:
				return nil, fmt.Errorf("invalid hex character: %c", c)
			}
		}
		data[i/2] = b
	}
	return data, nil
}

func parseScriptArgs(args string) map[string]string {
	m := make(map[string]string)
	for _, pair := range strings.Split(args, ",") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
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
