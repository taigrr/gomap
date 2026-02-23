//go:build linux

package gomap

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

const arpFile = "/proc/net/arp"

// arpCache stores the most recently loaded ARP table.
var (
	arpCache   map[string]ARPEntry
	arpCacheMu sync.RWMutex
)

// ARPEntry represents a single entry in the system ARP table.
type ARPEntry struct {
	IP     net.IP
	MAC    net.HardwareAddr
	Device *net.Interface
}

// String returns a human-readable representation of the ARP entry.
func (a ARPEntry) String() string {
	return fmt.Sprintf("%s\t%s\t%s", a.IP.String(), a.MAC.String(), a.Device.Name)
}

// LoadARPTable reads and parses the system ARP table from /proc/net/arp.
// This function is only available on Linux.
func LoadARPTable() (map[string]ARPEntry, error) {
	f, err := os.Open(arpFile)
	if err != nil {
		return nil, fmt.Errorf("opening ARP table: %w", err)
	}
	defer f.Close()

	table := make(map[string]ARPEntry)
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	count := 0
	for scanner.Scan() {
		count++
		if count == 1 {
			continue // skip header
		}
		line := scanner.Text()
		entry, err := ParseARPEntry(line)
		if err != nil {
			return nil, fmt.Errorf("parsing ARP entry: %w", err)
		}
		table[entry.MAC.String()] = entry
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	arpCacheMu.Lock()
	arpCache = table
	arpCacheMu.Unlock()

	return table, nil
}

// GetARPCache returns the most recently loaded ARP table.
// Call LoadARPTable first to populate the cache.
func GetARPCache() map[string]ARPEntry {
	arpCacheMu.RLock()
	defer arpCacheMu.RUnlock()
	return arpCache
}

// ParseARPEntry parses a single line from /proc/net/arp.
func ParseARPEntry(line string) (ARPEntry, error) {
	var a ARPEntry
	entries := strings.Fields(line)
	if len(entries) != 6 {
		return a, errors.New("invalid ARP entry: expected 6 fields")
	}
	a.IP = net.ParseIP(entries[0])
	if a.IP == nil {
		return a, fmt.Errorf("invalid IP address: %s", entries[0])
	}
	var err error
	a.MAC, err = net.ParseMAC(entries[3])
	if err != nil {
		return a, fmt.Errorf("invalid MAC address: %w", err)
	}
	a.Device, err = net.InterfaceByName(entries[5])
	if err != nil {
		return a, fmt.Errorf("interface %s: %w", entries[5], err)
	}
	return a, nil
}
