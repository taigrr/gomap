//go:build nonpsl

package gomap

import (
	"fmt"
	"net"
	"sync"

	"github.com/taigrr/gomap/probedb"
)

var (
	defaultProbeDB     *probedb.ServiceProbeDB
	defaultProbeDBOnce sync.Once
	defaultProbeDBErr  error
)

// DefaultProbeDB attempts to find and load nmap-service-probes from the system.
// When built with the "nonpsl" tag, no nmap data is embedded. The database
// is loaded from standard system paths or the GOMAP_DB_PATH environment variable.
func DefaultProbeDB() (*probedb.ServiceProbeDB, error) {
	defaultProbeDBOnce.Do(func() {
		sp, _ := probedb.FindDatabases()
		if sp == "" {
			defaultProbeDBErr = fmt.Errorf("no nmap-service-probes found on system (set GOMAP_DB_PATH or use --service-probes flag)")
			return
		}
		defaultProbeDB, defaultProbeDBErr = probedb.LoadServiceProbesFile(sp)
	})
	return defaultProbeDB, defaultProbeDBErr
}

// LookupMACVendor is a no-op when built with the nonpsl tag.
// Returns empty string. Use --service-probes to load data at runtime.
func LookupMACVendor(mac string) string {
	return ""
}

// LookupMACVendorHW is a no-op when built with the nonpsl tag.
func LookupMACVendorHW(mac net.HardwareAddr) string {
	return ""
}

// MACPrefixes returns nil when built with the nonpsl tag.
func MACPrefixes() map[string]string {
	return nil
}
