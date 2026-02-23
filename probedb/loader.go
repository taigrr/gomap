package probedb

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// LoadServiceProbesFile loads service probes from a file path.
func LoadServiceProbesFile(path string) (*ServiceProbeDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening service probes file: %w", err)
	}
	defer f.Close()
	return ParseServiceProbes(f)
}

// LoadServiceProbesData loads service probes from raw bytes (e.g., from go:embed).
func LoadServiceProbesData(data []byte) (*ServiceProbeDB, error) {
	return ParseServiceProbes(bytes.NewReader(data))
}

// LoadServiceProbesFS loads service probes from an fs.FS (for go:embed).
func LoadServiceProbesFS(fsys fs.FS, name string) (*ServiceProbeDB, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, fmt.Errorf("opening service probes from FS: %w", err)
	}
	defer f.Close()
	return ParseServiceProbes(f)
}

// LoadOSDBFile loads OS fingerprints from a file path.
func LoadOSDBFile(path string) (*OSDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening OS database file: %w", err)
	}
	defer f.Close()
	return ParseOSDB(f)
}

// LoadOSDBData loads OS fingerprints from raw bytes (e.g., from go:embed).
func LoadOSDBData(data []byte) (*OSDB, error) {
	return ParseOSDB(bytes.NewReader(data))
}

// LoadOSDBFS loads OS fingerprints from an fs.FS (for go:embed).
func LoadOSDBFS(fsys fs.FS, name string) (*OSDB, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, fmt.Errorf("opening OS database from FS: %w", err)
	}
	defer f.Close()
	return ParseOSDB(f)
}

// FindDatabases searches common locations for nmap database files.
// Returns paths found for service probes and OS database.
func FindDatabases() (serviceProbes, osDB string) {
	searchPaths := []string{
		"/usr/share/nmap",
		"/usr/local/share/nmap",
		"/opt/homebrew/share/nmap",
		"/opt/nmap/share/nmap",
	}

	// Also check NMAP_DB_PATH env
	if envPath := os.Getenv("GOMAP_DB_PATH"); envPath != "" {
		searchPaths = append([]string{envPath}, searchPaths...)
	}

	for _, dir := range searchPaths {
		sp := dir + "/nmap-service-probes"
		if _, err := os.Stat(sp); err == nil {
			serviceProbes = sp
		}
		od := dir + "/nmap-os-db"
		if _, err := os.Stat(od); err == nil {
			osDB = od
		}
		if serviceProbes != "" && osDB != "" {
			return
		}
	}

	return
}

// Stats returns human-readable statistics about a service probe database.
func (db *ServiceProbeDB) Stats() string {
	totalMatches := 0
	totalSoftMatches := 0
	tcpProbes := 0
	udpProbes := 0

	for _, p := range db.Probes {
		totalMatches += len(p.Matches)
		totalSoftMatches += len(p.SoftMatches)
		if p.Protocol == "TCP" {
			tcpProbes++
		} else {
			udpProbes++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Service Probe Database:\n")
	fmt.Fprintf(&b, "  Probes: %d (%d TCP, %d UDP)\n", len(db.Probes), tcpProbes, udpProbes)
	fmt.Fprintf(&b, "  Matches: %d\n", totalMatches)
	fmt.Fprintf(&b, "  Soft matches: %d\n", totalSoftMatches)
	return b.String()
}

// Stats returns human-readable statistics about an OS fingerprint database.
func (db *OSDB) Stats() string {
	var b strings.Builder
	fmt.Fprintf(&b, "OS Fingerprint Database:\n")
	fmt.Fprintf(&b, "  Fingerprints: %d\n", len(db.Fingerprints))
	fmt.Fprintf(&b, "  Match point tests: %d\n", len(db.MatchPoints.Points))
	return b.String()
}
