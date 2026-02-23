package gomap

import (
	"encoding/xml"
	"fmt"
	"time"
)

// NmapRun is the top-level XML element, compatible with nmap's -oX format.
type NmapRun struct {
	XMLName          xml.Name     `xml:"nmaprun"`
	Scanner          string       `xml:"scanner,attr"`
	Args             string       `xml:"args,attr,omitempty"`
	Start            int64        `xml:"start,attr"`
	StartStr         string       `xml:"startstr,attr"`
	Version          string       `xml:"version,attr"`
	XMLOutputVersion string       `xml:"xmloutputversion,attr"`
	ScanInfo         *XMLScanInfo `xml:"scaninfo,omitempty"`
	Verbose          XMLVerbose   `xml:"verbose"`
	Debugging        XMLDebugging `xml:"debugging"`
	Hosts            []XMLHost    `xml:"host"`
	RunStats         XMLRunStats  `xml:"runstats"`
}

// XMLScanInfo describes the scan parameters.
type XMLScanInfo struct {
	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	NumServices int    `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
}

// XMLVerbose is the verbose level element.
type XMLVerbose struct {
	Level int `xml:"level,attr"`
}

// XMLDebugging is the debug level element.
type XMLDebugging struct {
	Level int `xml:"level,attr"`
}

// XMLHost represents a scanned host.
type XMLHost struct {
	StartTime int64        `xml:"starttime,attr,omitempty"`
	EndTime   int64        `xml:"endtime,attr,omitempty"`
	Status    XMLStatus    `xml:"status"`
	Address   XMLAddress   `xml:"address"`
	Hostnames XMLHostnames `xml:"hostnames"`
	Ports     *XMLPorts    `xml:"ports,omitempty"`
	OS        *XMLOS       `xml:"os,omitempty"`
	Times     *XMLTimes    `xml:"times,omitempty"`
}

// XMLStatus describes whether the host is up/down.
type XMLStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// XMLAddress is an IP or MAC address.
type XMLAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

// XMLHostnames contains hostname entries.
type XMLHostnames struct {
	Hostnames []XMLHostname `xml:"hostname,omitempty"`
}

// XMLHostname is a single hostname entry.
type XMLHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// XMLPorts contains port scan results.
type XMLPorts struct {
	Ports []XMLPort `xml:"port"`
}

// XMLPort represents a single port result.
type XMLPort struct {
	Protocol string     `xml:"protocol,attr"`
	PortID   int        `xml:"portid,attr"`
	State    XMLState   `xml:"state"`
	Service  XMLService `xml:"service"`
}

// XMLState describes a port's state.
type XMLState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// XMLService describes the service running on a port.
type XMLService struct {
	Name string `xml:"name,attr"`
}

// XMLOS contains OS detection results.
type XMLOS struct {
	OSFingerprint []XMLOSFingerprint `xml:"osfingerprint,omitempty"`
}

// XMLOSFingerprint contains a raw OS fingerprint.
type XMLOSFingerprint struct {
	Fingerprint string `xml:"fingerprint,attr"`
}

// XMLTimes contains timing information.
type XMLTimes struct {
	SRTT string `xml:"srtt,attr"`
	RTT  string `xml:"rttvar,attr"`
	To   string `xml:"to,attr"`
}

// XMLRunStats contains scan statistics.
type XMLRunStats struct {
	Finished XMLFinished `xml:"finished"`
	Hosts    XMLHostStat `xml:"hosts"`
}

// XMLFinished contains scan completion info.
type XMLFinished struct {
	Time    int64  `xml:"time,attr"`
	TimeStr string `xml:"timestr,attr"`
	Elapsed string `xml:"elapsed,attr"`
	Summary string `xml:"summary,attr,omitempty"`
}

// XMLHostStat summarizes host counts.
type XMLHostStat struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

// ToXML converts a ScanResult to nmap-compatible XML.
func (r *ScanResult) ToXML(scanType ScanType, startTime time.Time, version string) ([]byte, error) {
	return resultsToXML([]*ScanResult{r}, scanType, startTime, version)
}

// ToXML converts a RangeScanResult to nmap-compatible XML.
func (results RangeScanResult) ToXML(scanType ScanType, startTime time.Time, version string) ([]byte, error) {
	return resultsToXML(results, scanType, startTime, version)
}

func resultsToXML(results []*ScanResult, scanType ScanType, startTime time.Time, version string) ([]byte, error) {
	now := time.Now()

	nmapRun := NmapRun{
		Scanner:          "gomap",
		Start:            startTime.Unix(),
		StartStr:         startTime.Format(time.RFC1123),
		Version:          version,
		XMLOutputVersion: "1.05",
		ScanInfo: &XMLScanInfo{
			Type:     scanType.String(),
			Protocol: "tcp",
		},
		Verbose:   XMLVerbose{Level: 0},
		Debugging: XMLDebugging{Level: 0},
	}

	upCount := 0
	for _, r := range results {
		host := XMLHost{
			StartTime: startTime.Unix(),
			EndTime:   now.Unix(),
		}

		// Address
		if len(r.IP) > 0 {
			host.Address = XMLAddress{
				Addr:     r.IP[len(r.IP)-1].String(),
				AddrType: "ipv4",
			}
		}

		// Status
		hasOpen := r.HasOpenPorts()
		if hasOpen {
			host.Status = XMLStatus{State: "up", Reason: "syn-ack"}
			upCount++
		} else {
			host.Status = XMLStatus{State: "up", Reason: "conn-refused"}
			upCount++
		}

		// Hostnames
		if r.Hostname != "" && r.Hostname != "Unknown" {
			host.Hostnames = XMLHostnames{
				Hostnames: []XMLHostname{
					{Name: r.Hostname, Type: "PTR"},
				},
			}
		}

		// Ports
		if len(r.Ports) > 0 {
			ports := &XMLPorts{}
			for _, p := range r.Ports {
				state := p.State.String()
				reason := "no-response"
				switch p.State {
				case PortOpen:
					reason = "syn-ack"
				case PortClosed:
					reason = "conn-refused"
				case PortFiltered:
					reason = "no-response"
				case PortUnfiltered:
					reason = "reset"
				case PortOpenFiltered:
					reason = "no-response"
				}

				svcName := p.Service
				if svcName == "" || svcName == "unknown" {
					svcName = LookupService(p.Port)
				}

				ports.Ports = append(ports.Ports, XMLPort{
					Protocol: "tcp",
					PortID:   p.Port,
					State:    XMLState{State: state, Reason: reason},
					Service:  XMLService{Name: svcName},
				})
			}
			host.Ports = ports
		}

		nmapRun.Hosts = append(nmapRun.Hosts, host)
	}

	elapsed := now.Sub(startTime).Seconds()
	nmapRun.RunStats = XMLRunStats{
		Finished: XMLFinished{
			Time:    now.Unix(),
			TimeStr: now.Format(time.RFC1123),
			Elapsed: fmt.Sprintf("%.2f", elapsed),
			Summary: fmt.Sprintf("gomap done: %d hosts scanned in %.2f seconds", len(results), elapsed),
		},
		Hosts: XMLHostStat{
			Up:    upCount,
			Down:  len(results) - upCount,
			Total: len(results),
		},
	}

	// Count services for scaninfo
	if nmapRun.ScanInfo != nil {
		portSet := make(map[int]bool)
		for _, r := range results {
			for _, p := range r.Ports {
				portSet[p.Port] = true
			}
		}
		nmapRun.ScanInfo.NumServices = len(portSet)
	}

	output, err := xml.MarshalIndent(nmapRun, "", "  ")
	if err != nil {
		return nil, err
	}

	header := []byte(xml.Header)
	return append(header, output...), nil
}
