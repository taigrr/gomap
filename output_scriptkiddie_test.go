package gomap

import "testing"

func TestToScriptKiddie(t *testing.T) {
	input := "Nmap scan report"
	output := ToScriptKiddie(input)
	if output == input {
		t.Error("script kiddie output should differ from input")
	}
	if len(output) != len(input) {
		t.Errorf("script kiddie output length changed: %d vs %d", len(output), len(input))
	}
}
