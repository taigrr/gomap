package main

import (
	"bytes"
	"go/format"
	"slices"
	"testing"
)

func TestGenerateSourceFormatsTemplateOutput(t *testing.T) {
	source, err := generateSource(templateData{
		TCP: []entry{
			{Port: 1, Name: "TCP Port Service Multiplexer"},
			{Port: 80, Name: "World Wide Web HTTP"},
		},
		UDP: []entry{
			{Port: 53, Name: "Domain Name Server"},
		},
		TopTCP: []int{80, 1},
		TCPFreqs: []freqEntry{
			{Port: 1, Freq: "0.1"},
			{Port: 80, Freq: "0.9"},
		},
		UDPFreqs: []freqEntry{
			{Port: 53, Freq: "0.3"},
		},
	})
	if err != nil {
		t.Fatalf("generateSource returned error: %v", err)
	}

	formatted, err := format.Source(source)
	if err != nil {
		t.Fatalf("generated source is invalid Go: %v", err)
	}
	if !bytes.Equal(source, formatted) {
		t.Fatal("generated source was not formatted")
	}
}

func TestTopByFrequencySortsEqualFrequenciesByPort(t *testing.T) {
	ports := topByFrequency(map[int]service{
		443: {Frequency: 0.9},
		22:  {Frequency: 0.8},
		80:  {Frequency: 0.9},
		25:  {Frequency: 0.8},
	}, 4)

	want := []int{80, 443, 22, 25}
	if !slices.Equal(ports, want) {
		t.Fatalf("topByFrequency() = %v, want %v", ports, want)
	}
}
