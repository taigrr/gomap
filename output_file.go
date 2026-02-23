package gomap

import (
	"fmt"
	"os"
)

// OutputConfig configures file output destinations.
type OutputConfig struct {
	// NormalFile is the path for human-readable output (-oN).
	NormalFile string

	// XMLFile is the path for XML output (-oX).
	XMLFile string

	// GrepFile is the path for grepable output (-oG).
	GrepFile string

	// Append appends to output files instead of overwriting.
	Append bool
}

// HasFileOutput returns true if any file output is configured.
func (o *OutputConfig) HasFileOutput() bool {
	return o.NormalFile != "" || o.XMLFile != "" || o.GrepFile != ""
}

// WriteNormal writes human-readable output to the configured file.
func (o *OutputConfig) WriteNormal(data string) error {
	if o.NormalFile == "" {
		return nil
	}
	return o.writeFile(o.NormalFile, data)
}

// WriteXML writes XML output to the configured file.
func (o *OutputConfig) WriteXML(data []byte) error {
	if o.XMLFile == "" {
		return nil
	}
	return o.writeFile(o.XMLFile, string(data))
}

// WriteGrep writes grepable output to the configured file.
func (o *OutputConfig) WriteGrep(data string) error {
	if o.GrepFile == "" {
		return nil
	}
	return o.writeFile(o.GrepFile, data)
}

// WriteAll writes all configured output formats at once.
func (o *OutputConfig) WriteAll(normal string, xmlData []byte, grep string) error {
	if err := o.WriteNormal(normal); err != nil {
		return fmt.Errorf("writing normal output: %w", err)
	}
	if err := o.WriteXML(xmlData); err != nil {
		return fmt.Errorf("writing XML output: %w", err)
	}
	if err := o.WriteGrep(grep); err != nil {
		return fmt.Errorf("writing grepable output: %w", err)
	}
	return nil
}

func (o *OutputConfig) writeFile(path, data string) error {
	flag := os.O_WRONLY | os.O_CREATE
	if o.Append {
		flag |= os.O_APPEND
	} else {
		flag |= os.O_TRUNC
	}

	f, err := os.OpenFile(path, flag, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(data)
	return err
}
