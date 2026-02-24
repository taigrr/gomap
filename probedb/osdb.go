package probedb

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// OSDB is a parsed collection of OS fingerprints.
type OSDB struct {
	Fingerprints []OSDBEntry
	MatchPoints  MatchPointConfig
}

// OSDBEntry represents a single OS fingerprint from nmap-os-db.
type OSDBEntry struct {
	// Name is the fingerprint label (e.g., "Linux 5.4 - 5.10").
	Name string

	// Classes describe the OS family, generation, device type.
	Classes []OSClass

	// CPE entries for the OS.
	CPE []string

	// Tests maps test name (SEQ, OPS, WIN, ECN, T1-T7, U1, IE) to key-value pairs.
	Tests map[string]map[string]string
}

// OSClass describes an OS classification.
type OSClass struct {
	Vendor     string
	Family     string
	Generation string
	DeviceType string
}

// MatchPointConfig defines the scoring weights for each test and attribute.
type MatchPointConfig struct {
	// Maps test name → attribute name → point value.
	Points map[string]map[string]int
}

// ParseOSDB parses an nmap-os-db format file.
func ParseOSDB(r io.Reader) (*OSDB, error) {
	db := &OSDB{
		MatchPoints: MatchPointConfig{
			Points: make(map[string]map[string]int),
		},
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var current *OSDBEntry
	inMatchPoints := false

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip the version check line
		if strings.HasPrefix(line, "This nmap-os-db") {
			continue
		}

		// MatchPoints section
		if line == "MatchPoints" {
			inMatchPoints = true
			continue
		}

		if inMatchPoints {
			if strings.HasPrefix(line, "Fingerprint ") {
				inMatchPoints = false
				// Fall through to fingerprint parsing
			} else {
				parseMatchPointLine(line, &db.MatchPoints)
				continue
			}
		}

		switch {
		case strings.HasPrefix(line, "Fingerprint "):
			if current != nil {
				db.Fingerprints = append(db.Fingerprints, *current)
			}
			current = &OSDBEntry{
				Name:  strings.TrimPrefix(line, "Fingerprint "),
				Tests: make(map[string]map[string]string),
			}

		case strings.HasPrefix(line, "Class "):
			if current != nil {
				cls := parseOSClass(line[6:])
				current.Classes = append(current.Classes, cls)
			}

		case strings.HasPrefix(line, "CPE "):
			if current != nil {
				current.CPE = append(current.CPE, line[4:])
			}

		default:
			// Test lines like SEQ(...), OPS(...), WIN(...), T1(...), etc.
			if current != nil {
				name, attrs := parseTestLine(line)
				if name != "" {
					current.Tests[name] = attrs
				}
			}
		}
	}

	if current != nil {
		db.Fingerprints = append(db.Fingerprints, *current)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning OS database: %w", err)
	}

	return db, nil
}

// parseMatchPointLine parses a line like:
// SEQ(SP=25%GCD=75%ISR=25%TI=100%CI=50%II=100%SS=80%TS=100)
func parseMatchPointLine(line string, cfg *MatchPointConfig) {
	name, attrs := parseTestLine(line)
	if name == "" {
		return
	}
	if cfg.Points[name] == nil {
		cfg.Points[name] = make(map[string]int)
	}
	for k, v := range attrs {
		points, err := strconv.Atoi(v)
		if err == nil {
			cfg.Points[name][k] = points
		}
	}
}

// parseTestLine parses "NAME(K=V%K=V%...)" format.
func parseTestLine(line string) (string, map[string]string) {
	parenIdx := strings.IndexByte(line, '(')
	if parenIdx < 0 {
		return "", nil
	}
	name := line[:parenIdx]

	closeIdx := strings.LastIndexByte(line, ')')
	if closeIdx <= parenIdx {
		return name, nil
	}

	inner := line[parenIdx+1 : closeIdx]
	attrs := make(map[string]string)

	for _, pair := range strings.Split(inner, "%") {
		eqIdx := strings.IndexByte(pair, '=')
		if eqIdx < 0 {
			continue
		}
		key := pair[:eqIdx]
		val := pair[eqIdx+1:]
		attrs[key] = val
	}

	return name, attrs
}

// parseOSClass parses "Vendor | Family | Generation | DeviceType" format.
func parseOSClass(s string) OSClass {
	parts := strings.SplitN(s, " | ", 4)
	cls := OSClass{}
	if len(parts) >= 1 {
		cls.Vendor = strings.TrimSpace(parts[0])
	}
	if len(parts) >= 2 {
		cls.Family = strings.TrimSpace(parts[1])
	}
	if len(parts) >= 3 {
		cls.Generation = strings.TrimSpace(parts[2])
	}
	if len(parts) >= 4 {
		cls.DeviceType = strings.TrimSpace(parts[3])
	}
	return cls
}

// MatchOS scores a fingerprint against the database and returns matches.
// The fingerprint is a map of test name → attribute name → value (same format as OSDBEntry.Tests).
func (db *OSDB) MatchOS(fp map[string]map[string]string) []OSMatchResult {
	var results []OSMatchResult

	for i := range db.Fingerprints {
		entry := &db.Fingerprints[i]
		score, maxScore := scoreFingerprint(fp, entry, &db.MatchPoints)

		if maxScore == 0 {
			continue
		}

		accuracy := float64(score) / float64(maxScore)
		if accuracy < 0.5 {
			continue // skip low-confidence matches
		}

		results = append(results, OSMatchResult{
			Name:     entry.Name,
			Classes:  entry.Classes,
			CPE:      entry.CPE,
			Accuracy: accuracy,
			Score:    score,
			MaxScore: maxScore,
		})
	}

	// Sort by accuracy descending
	for i := 1; i < len(results); i++ {
		for j := i; j > 0 && results[j].Accuracy > results[j-1].Accuracy; j-- {
			results[j], results[j-1] = results[j-1], results[j]
		}
	}

	// Return top 10
	if len(results) > 10 {
		results = results[:10]
	}

	return results
}

// OSMatchResult is a scored OS match.
type OSMatchResult struct {
	Name     string
	Classes  []OSClass
	CPE      []string
	Accuracy float64
	Score    int
	MaxScore int
}

// scoreFingerprint computes the match score between a scan fingerprint and a DB entry.
func scoreFingerprint(fp map[string]map[string]string, entry *OSDBEntry, cfg *MatchPointConfig) (score, maxScore int) {
	for testName, testAttrs := range entry.Tests {
		pointsMap := cfg.Points[testName]
		if pointsMap == nil {
			continue
		}

		fpTest := fp[testName]

		for attrName, expectedVal := range testAttrs {
			points := pointsMap[attrName]
			if points == 0 {
				points = 10 // default weight
			}
			maxScore += points

			if fpTest == nil {
				continue
			}

			actualVal, ok := fpTest[attrName]
			if !ok {
				continue
			}

			if matchAttributeValue(actualVal, expectedVal) {
				score += points
			}
		}
	}

	return score, maxScore
}

// matchAttributeValue checks if an actual value matches an expected value.
// Expected values can contain ranges (A-B), alternatives (A|B), and hex values.
func matchAttributeValue(actual, expected string) bool {
	if actual == expected {
		return true
	}

	// Handle alternatives: "A|B|C"
	if strings.Contains(expected, "|") {
		for _, alt := range strings.Split(expected, "|") {
			if matchAttributeValue(actual, alt) {
				return true
			}
		}
		return false
	}

	// Handle ranges: "A-B" (hex)
	if strings.Contains(expected, "-") && !strings.HasPrefix(expected, "-") {
		parts := strings.SplitN(expected, "-", 2)
		low, err1 := strconv.ParseInt(parts[0], 16, 64)
		high, err2 := strconv.ParseInt(parts[1], 16, 64)
		actualInt, err3 := strconv.ParseInt(actual, 16, 64)

		if err1 == nil && err2 == nil && err3 == nil {
			return actualInt >= low && actualInt <= high
		}
	}

	return false
}
