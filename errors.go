package gomap

import "errors"

// Sentinel errors for common failure modes. Callers can use errors.Is()
// to distinguish error types programmatically.
var (
	// ErrRawSocketRequired is returned when a scan type needs raw sockets
	// but the process lacks sufficient privileges (root/CAP_NET_RAW on Linux).
	ErrRawSocketRequired = errors.New("raw socket required")

	// ErrLinuxRequired is returned when a feature is only available on Linux.
	ErrLinuxRequired = errors.New("feature requires Linux")

	// ErrResolveHost is returned when hostname resolution fails.
	ErrResolveHost = errors.New("host resolution failed")

	// ErrNoAddresses is returned when DNS resolves but yields no IP addresses.
	ErrNoAddresses = errors.New("no IP addresses for host")

	// ErrInvalidCIDR is returned when a CIDR string cannot be parsed.
	ErrInvalidCIDR = errors.New("invalid CIDR notation")

	// ErrInvalidPortSpec is returned when a port specification cannot be parsed.
	ErrInvalidPortSpec = errors.New("invalid port specification")

	// ErrScanCanceled is returned when a scan is canceled via context.
	ErrScanCanceled = errors.New("scan canceled")

	// ErrInvalidScanOptions is returned by Validate() when options are inconsistent.
	ErrInvalidScanOptions = errors.New("invalid scan options")
)
