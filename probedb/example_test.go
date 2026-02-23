package probedb_test

import (
	"embed"
	"fmt"
	"os"
	"strings"

	"github.com/taigrr/gomap/probedb"
)

// Example_embed shows how to use go:embed to bundle nmap databases
// into your binary at compile time.
//
// In a real application, you would have the nmap-service-probes and
// nmap-os-db files in your project and embed them:
//
//	//go:embed nmap-service-probes
//	var serviceProbesData []byte
//
//	//go:embed nmap-os-db
//	var osDBData []byte
//
//	func init() {
//	    db, _ := probedb.LoadServiceProbesData(serviceProbesData)
//	    osdb, _ := probedb.LoadOSDBData(osDBData)
//	}
func Example_embed() {
	// Demonstrate loading from raw bytes (same as go:embed would provide)
	data := []byte(`Probe TCP NULL q||
totalwaitms 6000
match ssh m|^SSH-| p/SSH server/
`)

	db, err := probedb.LoadServiceProbesData(data)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Printf("Loaded %d probes\n", len(db.Probes))
	fmt.Printf("First probe: %s (%s)\n", db.Probes[0].Name, db.Probes[0].Protocol)
	// Output:
	// Loaded 1 probes
	// First probe: NULL (TCP)
}

// Example_fs shows how to use go:embed with fs.FS for a directory of databases.
//
//	//go:embed data
//	var dbFS embed.FS
//
//	func loadDBs() {
//	    db, _ := probedb.LoadServiceProbesFS(dbFS, "data/nmap-service-probes")
//	    osdb, _ := probedb.LoadOSDBFS(dbFS, "data/nmap-os-db")
//	}

// Example_matchService shows how to match a service response against the probe database.
func Example_matchService() {
	data := []byte(`Probe TCP NULL q||
totalwaitms 6000
match ssh m|^SSH-([\d.]+)-OpenSSH[_-]([\w.]+)| p/OpenSSH/ v/$2/ i/protocol $1/
match ftp m|^220[- ].*FTP| p/FTP server/
`)

	db, _ := probedb.LoadServiceProbesData(data)

	// Simulate receiving an SSH banner
	response := []byte("SSH-2.0-OpenSSH_9.7p1")

	for _, probe := range db.Probes {
		for _, m := range probe.Matches {
			groups := m.Pattern.FindStringSubmatch(string(response))
			if groups != nil {
				vi := m.VersionInfo.Apply(groups)
				fmt.Printf("Service: %s\n", m.Service)
				fmt.Printf("Product: %s\n", vi.ProductName)
				fmt.Printf("Version: %s\n", vi.Version)
				return
			}
		}
	}
	// Output:
	// Service: ssh
	// Product: OpenSSH
	// Version: 9.7p1
}

// Silence unused import warnings.
var _ embed.FS
var _ = os.Stdout
var _ = strings.NewReader
