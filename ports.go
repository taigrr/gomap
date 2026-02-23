package gomap

// To regenerate services_generated.go with the latest IANA + nmap data:
//
//	go run ./cmd/generate-services/ -nmap-services /path/to/nmap-services -o services_generated.go
//
// The nmap-services file can be obtained from the nmap source:
//
//	git clone --depth=1 https://github.com/nmap/nmap.git /tmp/nmap
//	go run ./cmd/generate-services/ -nmap-services /tmp/nmap/nmap-services -o services_generated.go

// LookupService returns the service name for a given TCP port number.
// Returns "unknown" if no service is found.
func LookupService(port int) string {
	if svc, ok := TCPServices[port]; ok {
		return svc
	}
	return "unknown"
}

// LookupUDPService returns the service name for a given UDP port number.
func LookupUDPService(port int) string {
	if svc, ok := UDPServices[port]; ok {
		return svc
	}
	return "unknown"
}

// CommonPorts maps the top TCP ports to service names for fast scanning.
var CommonPorts map[int]string

// DetailedPorts is the full TCP service map for comprehensive scans.
var DetailedPorts map[int]string

func init() {
	CommonPorts = make(map[int]string, len(TopTCPPorts))
	for _, port := range TopTCPPorts {
		CommonPorts[port] = LookupService(port)
	}
	DetailedPorts = TCPServices
}
