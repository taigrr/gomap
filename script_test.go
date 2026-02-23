package gomap

import (
	"context"
	"testing"
)

func TestScriptEngineRegister(t *testing.T) {
	e := NewScriptEngine()
	e.Register(&httpTitleScript{})
	e.Register(&sshHostKeyScript{})
	e.Register(&sslCertScript{})

	ids := e.ListScripts()
	if len(ids) != 3 {
		t.Fatalf("expected 3 scripts, got %d", len(ids))
	}
}

func TestScriptEngineSelectByCategory(t *testing.T) {
	scripts := DefaultEngine.SelectByCategory(CategoryDefault)
	if len(scripts) == 0 {
		t.Error("expected default category scripts")
	}
	for _, s := range scripts {
		found := false
		for _, c := range s.Categories() {
			if c == CategoryDefault {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("script %s selected but not in default category", s.ID())
		}
	}
}

func TestScriptEngineSelectByIDs(t *testing.T) {
	scripts := DefaultEngine.SelectByIDs("http-title")
	if len(scripts) != 1 {
		t.Fatalf("expected 1 script, got %d", len(scripts))
	}
	if scripts[0].ID() != "http-title" {
		t.Errorf("got script %s, want http-title", scripts[0].ID())
	}
}

func TestScriptEngineGlob(t *testing.T) {
	scripts := DefaultEngine.SelectByIDs("http-*")
	if len(scripts) == 0 {
		t.Error("expected http-* to match at least one script")
	}
}

func TestScriptMatch(t *testing.T) {
	s := &httpTitleScript{}
	if !s.Match(ScriptTarget{Port: 80}) {
		t.Error("http-title should match port 80")
	}
	if !s.Match(ScriptTarget{Service: "https"}) {
		t.Error("http-title should match service https")
	}
	if s.Match(ScriptTarget{Port: 22, Service: "ssh"}) {
		t.Error("http-title should not match SSH")
	}
}

func TestScriptRunScriptsEmpty(t *testing.T) {
	e := NewScriptEngine()
	outputs := e.RunScripts(context.Background(), nil, ScriptTarget{}, 4)
	if len(outputs) != 0 {
		t.Errorf("expected no outputs, got %d", len(outputs))
	}
}

func TestScriptOutputString(t *testing.T) {
	out := ScriptOutput{
		ScriptID: "test-script",
		Output:   "hello world",
	}
	s := out.String()
	if s != "| test-script: hello world" {
		t.Errorf("unexpected output: %q", s)
	}
}

func TestExtractHTMLTitle(t *testing.T) {
	tests := []struct {
		html string
		want string
	}{
		{"<html><head><title>Hello World</title></head></html>", "Hello World"},
		{"<title>  Spaced  Title  </title>", "Spaced Title"},
		{"<html>no title here</html>", ""},
		{"<TITLE>Case Insensitive</TITLE>", "Case Insensitive"},
	}
	for _, tt := range tests {
		got := extractHTMLTitle(tt.html)
		if got != tt.want {
			t.Errorf("extractHTMLTitle(%q) = %q, want %q", tt.html[:20], got, tt.want)
		}
	}
}
