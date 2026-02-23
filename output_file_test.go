package gomap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOutputConfigWriteNormal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.nmap")

	oc := &OutputConfig{NormalFile: path}
	if err := oc.WriteNormal("hello world\n"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello world\n" {
		t.Errorf("got %q", string(data))
	}
}

func TestOutputConfigAppend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.nmap")

	oc := &OutputConfig{NormalFile: path, Append: true}
	oc.WriteNormal("line1\n")
	oc.WriteNormal("line2\n")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "line1\nline2\n" {
		t.Errorf("got %q, want line1+line2", string(data))
	}
}

func TestOutputConfigWriteAll(t *testing.T) {
	dir := t.TempDir()
	oc := &OutputConfig{
		NormalFile: filepath.Join(dir, "out.nmap"),
		XMLFile:    filepath.Join(dir, "out.xml"),
		GrepFile:   filepath.Join(dir, "out.gnmap"),
	}

	err := oc.WriteAll("normal", []byte("<xml/>"), "grep")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		path string
		want string
	}{
		{oc.NormalFile, "normal"},
		{oc.XMLFile, "<xml/>"},
		{oc.GrepFile, "grep"},
	} {
		data, err := os.ReadFile(tc.path)
		if err != nil {
			t.Errorf("reading %s: %v", tc.path, err)
		}
		if string(data) != tc.want {
			t.Errorf("%s: got %q, want %q", tc.path, string(data), tc.want)
		}
	}
}

func TestOutputConfigHasFileOutput(t *testing.T) {
	if (&OutputConfig{}).HasFileOutput() {
		t.Error("empty config should return false")
	}
	if !(&OutputConfig{NormalFile: "x"}).HasFileOutput() {
		t.Error("with NormalFile should return true")
	}
}

func TestSetStateReason(t *testing.T) {
	p := PortResult{Port: 80}
	p.setStateReason(PortOpen, "syn-ack")
	if p.State != PortOpen || !p.Open || p.Reason != "syn-ack" {
		t.Errorf("setStateReason(Open, syn-ack) = {%v, %v, %q}", p.State, p.Open, p.Reason)
	}

	p.setStateReason(PortClosed, "reset")
	if p.State != PortClosed || p.Open || p.Reason != "reset" {
		t.Errorf("setStateReason(Closed, reset) = {%v, %v, %q}", p.State, p.Open, p.Reason)
	}
}
