//go:build !nonpsl

package gomap

import (
	"bytes"
	"net"
	"sync"

	nmapprobes "github.com/taigrr/nmap-probes"

	"github.com/taigrr/gomap/probedb"
)

var (
	defaultProbeDB     *probedb.ServiceProbeDB
	defaultProbeDBOnce sync.Once
	defaultProbeDBErr  error

	defaultOSDB     *probedb.OSDB
	defaultOSDBOnce sync.Once
	defaultOSDBErr  error
)

// DefaultProbeDB returns the embedded nmap service probe database.
// Parsed lazily on first call and cached.
func DefaultProbeDB() (*probedb.ServiceProbeDB, error) {
	defaultProbeDBOnce.Do(func() {
		data := nmapprobes.ServiceProbes()
		defaultProbeDB, defaultProbeDBErr = probedb.ParseServiceProbes(bytes.NewReader(data))
	})
	return defaultProbeDB, defaultProbeDBErr
}

// DefaultOSDB returns the embedded nmap OS fingerprint database.
// Parsed lazily on first call and cached.
func DefaultOSDB() (*probedb.OSDB, error) {
	defaultOSDBOnce.Do(func() {
		data := nmapprobes.OSFingerprints()
		defaultOSDB, defaultOSDBErr = probedb.ParseOSDB(bytes.NewReader(data))
	})
	return defaultOSDB, defaultOSDBErr
}

// LookupMACVendor returns the vendor name for a given MAC address.
func LookupMACVendor(mac string) string {
	return nmapprobes.LookupMAC(mac)
}

// LookupMACVendorHW returns the vendor name for a net.HardwareAddr.
func LookupMACVendorHW(mac net.HardwareAddr) string {
	return nmapprobes.LookupMACHW(mac)
}

// MACPrefixes returns the full OUI-to-vendor map from the embedded database.
func MACPrefixes() map[string]string {
	return nmapprobes.MACPrefixes()
}
