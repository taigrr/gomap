package gomap

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"

	"github.com/taigrr/gomap/probedb"
)

var (
	defaultProbeDB     *probedb.ServiceProbeDB
	defaultProbeDBOnce sync.Once
	defaultProbeDBErr  error
)

// DefaultProbeDB returns the embedded service probe database.
// The database is parsed lazily on first call and cached.
func DefaultProbeDB() (*probedb.ServiceProbeDB, error) {
	defaultProbeDBOnce.Do(func() {
		defaultProbeDB, defaultProbeDBErr = loadEmbeddedProbes()
	})
	return defaultProbeDB, defaultProbeDBErr
}

// serializedProbe mirrors the generator's output format.
type serializedProbe struct {
	Name         string            `json:"name"`
	Protocol     string            `json:"protocol"`
	ProbeString  string            `json:"probe_string"`
	Rarity       int               `json:"rarity"`
	Ports        string            `json:"ports"`
	SSLPorts     string            `json:"ssl_ports,omitempty"`
	TotalWaitMS  int               `json:"total_wait_ms"`
	TCPWrappedMS int               `json:"tcp_wrapped_ms,omitempty"`
	Fallback     string            `json:"fallback,omitempty"`
	Matches      []serializedMatch `json:"matches,omitempty"`
	SoftMatches  []serializedMatch `json:"soft_matches,omitempty"`
}

type serializedMatch struct {
	Service     string   `json:"service"`
	Pattern     string   `json:"pattern"`
	Flags       string   `json:"flags,omitempty"`
	ProductName string   `json:"product,omitempty"`
	Version     string   `json:"version,omitempty"`
	Info        string   `json:"info,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	OS          string   `json:"os,omitempty"`
	DeviceType  string   `json:"device,omitempty"`
	CPE         []string `json:"cpe,omitempty"`
}

func loadEmbeddedProbes() (*probedb.ServiceProbeDB, error) {
	var probes []serializedProbe
	if err := json.Unmarshal([]byte(embeddedServiceProbesJSON), &probes); err != nil {
		return nil, fmt.Errorf("parsing embedded probe data: %w", err)
	}

	db := &probedb.ServiceProbeDB{}
	for _, sp := range probes {
		p := probedb.ServiceProbe{
			Name:         sp.Name,
			Protocol:     sp.Protocol,
			Rarity:       sp.Rarity,
			Ports:        probedb.NewPortSet(sp.Ports),
			SSLPorts:     probedb.NewPortSet(sp.SSLPorts),
			TotalWaitMS:  sp.TotalWaitMS,
			TCPWrappedMS: sp.TCPWrappedMS,
			Fallback:     sp.Fallback,
		}

		// Decode hex probe string
		if sp.ProbeString != "" {
			decoded, err := hex.DecodeString(sp.ProbeString)
			if err != nil {
				return nil, fmt.Errorf("decoding probe %s payload: %w", sp.Name, err)
			}
			p.ProbeString = decoded
		}

		// Compile matches
		for _, sm := range sp.Matches {
			m, err := deserializeMatch(sm)
			if err != nil {
				continue // skip patterns that fail to compile
			}
			p.Matches = append(p.Matches, m)
		}
		for _, sm := range sp.SoftMatches {
			m, err := deserializeMatch(sm)
			if err != nil {
				continue
			}
			p.SoftMatches = append(p.SoftMatches, m)
		}

		db.Probes = append(db.Probes, p)
	}

	return db, nil
}

func deserializeMatch(sm serializedMatch) (probedb.ServiceMatch, error) {
	flags := "(?s"
	if len(sm.Flags) > 0 {
		for _, f := range sm.Flags {
			if f == 'i' {
				flags += "i"
			}
		}
	}
	flags += ")"

	compiled, err := regexp.Compile(flags + sm.Pattern)
	if err != nil {
		return probedb.ServiceMatch{}, err
	}

	return probedb.ServiceMatch{
		Service:    sm.Service,
		Pattern:    compiled,
		PatternStr: sm.Pattern,
		Flags:      sm.Flags,
		VersionInfo: probedb.VersionInfo{
			ProductName: sm.ProductName,
			Version:     sm.Version,
			Info:        sm.Info,
			Hostname:    sm.Hostname,
			OS:          sm.OS,
			DeviceType:  sm.DeviceType,
			CPE:         sm.CPE,
		},
	}, nil
}
