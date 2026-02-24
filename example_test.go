package gomap_test

import (
	"fmt"
	"time"

	"github.com/taigrr/gomap"
)

func ExampleParsePortRange() {
	ports, err := gomap.ParsePortRange("22,80,443")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(ports)
	// Output:
	// [22 80 443]
}

func ExampleParsePortRange_range() {
	ports, err := gomap.ParsePortRange("80-82")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(ports)
	// Output:
	// [80 81 82]
}

func ExampleLookupService() {
	fmt.Println(gomap.LookupService(22))
	fmt.Println(gomap.LookupService(80))
	fmt.Println(gomap.LookupService(443))
	// Output:
	// The Secure Shell (SSH) Protocol
	// World Wide Web HTTP
	// http protocol over TLS/SSL
}

func ExampleCreateHostRange() {
	hosts := gomap.CreateHostRange("192.168.1.0/30")
	fmt.Println(hosts)
	// Output:
	// [192.168.1.1 192.168.1.2]
}

func ExampleApplyTiming() {
	opts := gomap.ScanOptions{}
	gomap.ApplyTiming(&opts, gomap.TimingAggressive)
	fmt.Printf("Timeout: %s, Workers: %d\n", opts.Timeout, opts.Workers)
	// Output:
	// Timeout: 1.25s, Workers: 1000
}

func ExampleParseTimingTemplate() {
	tmpl, err := gomap.ParseTimingTemplate("T4")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(tmpl)
	// Output:
	// aggressive
}

func ExampleParseDecoys() {
	dc, err := gomap.ParseDecoys("RND,ME,RND", "192.168.1.100")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	ips := dc.ResolvedIPs()
	fmt.Printf("Decoy count: %d\n", len(ips))
	fmt.Printf("Real IP at index 1: %s\n", ips[1])
	// Output:
	// Decoy count: 3
	// Real IP at index 1: 192.168.1.100
}

func ExampleScanResult_OpenPorts() {
	result := &gomap.ScanResult{
		Hostname: "example.com",
		Ports: []gomap.PortResult{
			{Port: 22, Open: true, Service: "ssh"},
			{Port: 23, Open: false, Service: "telnet"},
			{Port: 80, Open: true, Service: "http"},
		},
	}
	for _, port := range result.OpenPorts() {
		fmt.Printf("%d/%s\n", port.Port, port.Service)
	}
	// Output:
	// 22/ssh
	// 80/http
}

func ExampleNewScriptEngine() {
	engine := gomap.NewScriptEngine()
	fmt.Printf("Scripts: %d\n", len(engine.ListScripts()))
	// Output:
	// Scripts: 0
}

func ExampleIsIPv6() {
	fmt.Println(gomap.IsIPv6("192.168.1.1"))
	fmt.Println(gomap.IsIPv6("::1"))
	fmt.Println(gomap.IsIPv6("2001:db8::1"))
	// Output:
	// false
	// true
	// true
}

// ExampleScanOptions_Validate demonstrates early validation of scan options.
func ExampleScanOptions_Validate() {
	opts := gomap.ScanOptions{
		VersionIntensity: 15, // invalid: must be 0-9
	}
	err := opts.Validate()
	fmt.Println(err)
	// Output:
	// invalid scan options: version-intensity must be 0-9, got 15
}

// ExamplePortsByRatio shows selecting ports by open-frequency ratio.
func ExamplePortsByRatio() {
	ports := gomap.PortsByRatio(0.01) // ports open >1% of the time
	fmt.Printf("Ports with >1%% open ratio: %d\n", len(ports))
}

// Silence unused import warning.
var _ = time.Second
