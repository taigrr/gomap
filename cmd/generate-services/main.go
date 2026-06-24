// Command generate-services builds a Go source file containing port-to-service
// mappings from two sources:
//   - IANA Service Name and Transport Protocol Port Number Registry (CSV)
//   - nmap-services file (for frequency data and additional services)
//
// The IANA registry provides the canonical service names. The nmap-services
// file adds frequency data (probability of a port being open) and fills gaps
// where IANA has no entry.
//
//go:generate go run . -o ../../services_generated.go
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"
)

const (
	ianaURL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
	nmapURL = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"
)

type service struct {
	Name      string
	Port      int
	Protocol  string
	Frequency float64
}

func main() {
	output := flag.String("o", "services_generated.go", "Output file path")
	nmapFile := flag.String("nmap-services", "", "Path to nmap-services file (optional, adds frequency data)")
	flag.Parse()

	tcpServices := make(map[int]service)
	udpServices := make(map[int]service)

	// Step 1: Load nmap-services (frequency data + extra services)
	if *nmapFile != "" {
		log.Printf("Loading nmap-services from %s", *nmapFile)
		loadNmapServices(*nmapFile, tcpServices, udpServices)
	} else {
		log.Printf("Fetching nmap-services from %s", nmapURL)
		loadNmapServicesURL(nmapURL, tcpServices, udpServices)
	}
	log.Printf("Loaded %d TCP, %d UDP from nmap-services", len(tcpServices), len(udpServices))

	// Step 2: Overlay IANA data (canonical names take priority)
	log.Printf("Fetching IANA service registry from %s", ianaURL)
	loadIANA(tcpServices, udpServices)
	log.Printf("After IANA merge: %d TCP, %d UDP services", len(tcpServices), len(udpServices))

	// Step 3: Sort and generate
	tcpEntries := sortByPort(tcpServices)
	udpEntries := sortByPort(udpServices)

	// Step 4: Generate top ports by frequency
	topTCP := topByFrequency(tcpServices, 1000)

	// Step 5: Generate frequency maps
	tcpFreqs := freqEntries(tcpServices)
	udpFreqs := freqEntries(udpServices)

	data := templateData{
		Generated: time.Now().UTC().Format(time.RFC3339),
		TCP:       tcpEntries,
		UDP:       udpEntries,
		TopTCP:    topTCP,
		TCPFreqs:  tcpFreqs,
		UDPFreqs:  udpFreqs,
	}

	f, err := os.Create(*output)
	if err != nil {
		log.Fatalf("creating output file: %v", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		log.Fatalf("executing template: %v", err)
	}

	log.Printf("Generated %s (%d TCP, %d UDP, top %d ports)", *output, len(tcpEntries), len(udpEntries), len(topTCP))
}

func loadNmapServices(path string, tcp, udp map[int]service) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("opening nmap-services: %v", err)
	}
	defer f.Close()

	loadNmapServicesReader(f, tcp, udp)
}

func loadNmapServicesURL(url string, tcp, udp map[int]service) {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("fetching nmap-services: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		log.Fatalf("fetching nmap-services: unexpected status %s", resp.Status)
	}

	loadNmapServicesReader(resp.Body, tcp, udp)
}

func loadNmapServicesReader(reader io.Reader, tcp, udp map[int]service) {
	data, err := io.ReadAll(reader)
	if err != nil {
		log.Fatalf("reading nmap-services: %v", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		name := fields[0]
		portProto := strings.SplitN(fields[1], "/", 2)
		if len(portProto) != 2 {
			continue
		}

		port, err := strconv.Atoi(portProto[0])
		if err != nil {
			continue
		}

		proto := portProto[1]
		freq, _ := strconv.ParseFloat(fields[2], 64)

		// Extract comment if present
		desc := name
		for i, f := range fields {
			if f == "#" && i+1 < len(fields) {
				desc = strings.Join(fields[i+1:], " ")
				break
			}
		}

		svc := service{
			Name:      desc,
			Port:      port,
			Protocol:  proto,
			Frequency: freq,
		}

		switch proto {
		case "tcp":
			tcp[port] = svc
		case "udp":
			udp[port] = svc
		}
	}
}

func loadIANA(tcp, udp map[int]service) {
	resp, err := http.Get(ianaURL)
	if err != nil {
		log.Fatalf("fetching IANA data: %v", err)
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)
	reader.LazyQuotes = true

	// Skip header
	if _, err := reader.Read(); err != nil {
		log.Fatalf("reading header: %v", err)
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		name := record[0]
		portStr := record[1]
		proto := record[2]
		desc := record[3]

		if name == "" || portStr == "" || proto == "" {
			continue
		}
		if strings.Contains(portStr, "-") {
			continue
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		displayName := desc
		if displayName == "" {
			displayName = name
		}

		var target map[int]service
		switch proto {
		case "tcp":
			target = tcp
		case "udp":
			target = udp
		default:
			continue
		}

		if existing, ok := target[port]; ok {
			// Keep nmap frequency but use IANA name
			existing.Name = displayName
			target[port] = existing
		} else {
			target[port] = service{
				Name:     displayName,
				Port:     port,
				Protocol: proto,
			}
		}
	}
}

func sortByPort(m map[int]service) []entry {
	ports := make([]int, 0, len(m))
	for p := range m {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	entries := make([]entry, 0, len(ports))
	for _, p := range ports {
		svc := m[p]
		entries = append(entries, entry{Port: p, Name: svc.Name})
	}
	return entries
}

func topByFrequency(m map[int]service, n int) []int {
	type pf struct {
		port int
		freq float64
	}

	var pfs []pf
	for port, svc := range m {
		if svc.Frequency > 0 {
			pfs = append(pfs, pf{port, svc.Frequency})
		}
	}

	sort.Slice(pfs, func(i, j int) bool {
		return pfs[i].freq > pfs[j].freq
	})

	if len(pfs) > n {
		pfs = pfs[:n]
	}

	result := make([]int, len(pfs))
	for i, p := range pfs {
		result[i] = p.port
	}
	return result
}

type templateData struct {
	Generated string
	TCP       []entry
	UDP       []entry
	TopTCP    []int
	TCPFreqs  []freqEntry
	UDPFreqs  []freqEntry
}

type entry struct {
	Port int
	Name string
}

type freqEntry struct {
	Port int
	Freq string // formatted as Go float literal
}

func freqEntries(m map[int]service) []freqEntry {
	ports := make([]int, 0, len(m))
	for p, svc := range m {
		if svc.Frequency > 0 {
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)

	entries := make([]freqEntry, 0, len(ports))
	for _, p := range ports {
		entries = append(entries, freqEntry{
			Port: p,
			Freq: fmt.Sprintf("%g", m[p].Frequency),
		})
	}
	return entries
}

var tmpl = template.Must(template.New("services").Parse(`// Code generated by generate-services; DO NOT EDIT.
// Sources:
//   - IANA Service Name and Transport Protocol Port Number Registry
//   - nmap-services (frequency data)
// Generated: {{ .Generated }}

package gomap

// TCPServices maps TCP port numbers to service names.
// Names are sourced from IANA where available, with nmap-services filling gaps.
var TCPServices = map[int]string{
{{- range .TCP }}
	{{ .Port }}: {{ printf "%q" .Name }},
{{- end }}
}

// UDPServices maps UDP port numbers to service names.
var UDPServices = map[int]string{
{{- range .UDP }}
	{{ .Port }}: {{ printf "%q" .Name }},
{{- end }}
}

// TopTCPPorts contains the top {{ len .TopTCP }} most commonly open TCP ports,
// sorted by frequency (probability of being found open). Derived from
// empirical scanning data in nmap-services.
var TopTCPPorts = []int{
{{- range $i, $port := .TopTCP }}
	{{ $port }},
{{- end }}
}

// TCPPortFrequency maps TCP port numbers to their open frequency (0.0-1.0).
// Derived from nmap-services empirical scanning data.
var TCPPortFrequency = map[int]float64{
{{- range .TCPFreqs }}
	{{ .Port }}: {{ .Freq }},
{{- end }}
}

// UDPPortFrequency maps UDP port numbers to their open frequency (0.0-1.0).
var UDPPortFrequency = map[int]float64{
{{- range .UDPFreqs }}
	{{ .Port }}: {{ .Freq }},
{{- end }}
}
`))

func init() {
	_ = fmt.Sprint
}
