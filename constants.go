package gomap

const (
	// readBufferSize is the standard size for network read buffers throughout
	// the package. 1024 bytes is sufficient for protocol handshakes, banners,
	// and ICMP responses while keeping allocations small.
	readBufferSize = 1024

	// streamHostEventBuffer is the channel buffer size for ScanHostStream.
	// Sized to allow bursty port results without blocking workers while
	// keeping memory bounded. 64 balances throughput and memory for typical
	// scans of 100-1000 ports.
	streamHostEventBuffer = 64

	// streamCIDREventBuffer is the channel buffer size for ScanCIDRStream.
	// Larger than streamHostEventBuffer because multiple hosts produce
	// results concurrently.
	streamCIDREventBuffer = 128

	// discoveryStreamBuffer is the channel buffer size for DiscoverHostsStream.
	discoveryStreamBuffer = 64

	// ephemeralPortMin is the lower bound for random ephemeral source ports.
	ephemeralPortMin = 10000

	// ephemeralPortMax is the upper bound (exclusive) for random ephemeral source ports.
	ephemeralPortMax = 65535
)
