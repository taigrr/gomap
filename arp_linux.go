package gomap

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

const ArpFile = "/proc/net/arp"

var arpTable map[string]ArpEntry

func init() {
	arpTable = make(map[string]ArpEntry)
}

type ArpEntry struct {
	// IP address       HW type     Flags       HW address            Mask     Device
	IP     net.IP
	MAC    net.HardwareAddr
	Device *net.Interface
}

func (a ArpEntry) String() string {
	return fmt.Sprintf("%s\t%s\t%s", a.IP.String(), a.MAC.String(), a.Device.Name)
}

func LoadArpTable() error {
	arpFile, err := os.Open(ArpFile)
	if err != nil {
		return err
	}
	defer arpFile.Close()

	scanner := bufio.NewScanner(arpFile)
	scanner.Split(bufio.ScanLines)
	count := 0
	for scanner.Scan() {
		count++
		if count == 1 {
			continue
		}
		line := scanner.Text()
		entry, err := ParseArpEntry(line)
		if err != nil {
			return err
		}
		arpTable[entry.MAC.String()] = entry
	}
	return scanner.Err()
}

func ParseArpEntry(line string) (a ArpEntry, err error) {
	entries := strings.Fields(line)
	if len(entries) != 6 {
		return a, errors.New("invalid arp entry line")
	}
	a.IP = net.ParseIP(entries[0])
	a.MAC, err = net.ParseMAC(entries[3])
	if err != nil {
		return a, err
	}
	a.Device, err = net.InterfaceByName(entries[5])
	return
}
