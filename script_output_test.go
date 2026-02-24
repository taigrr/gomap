package gomap

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestScriptOutputStringWithElements(t *testing.T) {
	so := &ScriptOutput{
		ScriptID: "test-script",
		Elements: map[string]string{"key1": "val1", "key2": "val2"},
	}
	got := so.String()
	if !strings.Contains(got, "key1: val1") || !strings.Contains(got, "key2: val2") {
		t.Errorf("expected elements in output: %q", got)
	}
}

func TestScriptOutputStringWithError(t *testing.T) {
	so := &ScriptOutput{
		ScriptID: "test-script",
		Error:    errors.New("something broke"),
	}
	got := so.String()
	if !strings.Contains(got, "ERROR") || !strings.Contains(got, "something broke") {
		t.Errorf("expected error in output: %q", got)
	}
}

func TestScriptEngineRunScriptsContextCancel(t *testing.T) {
	engine := NewScriptEngine()
	engine.Register(&bannerScript{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	target := ScriptTarget{Host: "192.0.2.1", Port: 80, Service: "http"}
	scripts := engine.SelectByIDs("banner")
	outputs := engine.RunScripts(ctx, scripts, target, 1)
	_ = outputs // should not hang or panic
}

func TestExtractHTMLTitleEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{"empty title", "<html><title></title></html>", ""},
		{"unclosed title", "<html><title>Hello", ""},
		{"title with attributes", `<title lang="en">Attributed</title>`, "Attributed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHTMLTitle(tt.html)
			if got != tt.want {
				t.Errorf("extractHTMLTitle = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScriptEngineGetScript(t *testing.T) {
	engine := NewScriptEngine()
	engine.Register(&httpTitleScript{})

	script, ok := engine.GetScript("http-title")
	if !ok || script == nil {
		t.Error("expected to find http-title script")
	}

	_, ok = engine.GetScript("nonexistent")
	if ok {
		t.Error("expected false for nonexistent script")
	}
}
