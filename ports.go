package gomap

//go:generate go run ./cmd/generate-services/ -o services_generated.go

// LookupService returns the service name for a given TCP port number.
// It checks the IANA registry first, then falls back to common ports.
// Returns "unknown" if no service is found.
func LookupService(port int) string {
	if svc, ok := IANATCPServices[port]; ok {
		return svc
	}
	return "unknown"
}

// LookupUDPService returns the service name for a given UDP port number.
func LookupUDPService(port int) string {
	if svc, ok := IANAUDPServices[port]; ok {
		return svc
	}
	return "unknown"
}

// TopTCPPorts contains the most commonly open TCP ports, ordered by
// likelihood of being found open on the internet. This list is curated
// from empirical scanning data and is equivalent to nmap's --top-ports.
var TopTCPPorts = []int{
	// Top 100 TCP ports by frequency
	80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
	143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
	1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
	10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
	26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
	5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
	2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
	544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
	7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
	6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,

	// Ports 101-200
	1000, 3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103,
	6004, 1801, 5050, 19, 8031, 1041, 255, 1049, 1048, 2967,
	1053, 3703, 1056, 1065, 1064, 1054, 17, 808, 3689, 1031,
	1044, 1071, 5901, 100, 9102, 8010, 2869, 1039, 5120, 4001,
	9000, 2105, 636, 1038, 2601, 7000, 1, 1066, 1069, 625,
	311, 280, 254, 4000, 5003, 1761, 2002, 2005, 1998, 1032,
	1050, 6112, 3690, 1521, 2161, 6002, 1080, 2401, 4045, 902,
	7937, 787, 1058, 2383, 32771, 1033, 1040, 1059, 50000, 5555,
	10001, 1494, 593, 2301, 3268, 7938, 1022, 1234, 1035, 1036,
	1037, 1074, 8002, 9001, 464, 1935, 2003, 497, 6666, 6543,
}

// CommonPorts is an alias for TopTCPPorts as a map for quick lookup.
// Used during fast scans.
var CommonPorts map[int]string

func init() {
	CommonPorts = make(map[int]string, len(TopTCPPorts))
	for _, port := range TopTCPPorts {
		CommonPorts[port] = LookupService(port)
	}
}

// AllTCPPorts returns the full IANA TCP service map for detailed scans.
// This is used when FastScan is false and no custom Ports are specified.
var DetailedPorts = IANATCPServices
