package gomap

import "testing"

func TestExtraScriptsRegistered(t *testing.T) {
	expected := []string{
		"banner", "ftp-anon", "http-headers", "http-robots",
		"mysql-info", "redis-info", "smtp-commands",
	}
	for _, id := range expected {
		if _, ok := DefaultEngine.GetScript(id); !ok {
			t.Errorf("script %q not registered", id)
		}
	}
}

func TestExtraScriptsMatch(t *testing.T) {
	tests := []struct {
		id   string
		port int
		svc  string
		want bool
	}{
		{"smtp-commands", 25, "", true},
		{"smtp-commands", 587, "", true},
		{"smtp-commands", 80, "", false},
		{"ftp-anon", 21, "", true},
		{"ftp-anon", 80, "", false},
		{"mysql-info", 3306, "", true},
		{"redis-info", 6379, "", true},
		{"http-headers", 80, "", true},
		{"http-headers", 443, "", true},
		{"http-robots", 80, "", true},
		{"banner", 12345, "", true}, // matches anything
	}

	for _, tt := range tests {
		s, ok := DefaultEngine.GetScript(tt.id)
		if !ok {
			t.Errorf("script %q not found", tt.id)
			continue
		}
		target := ScriptTarget{Port: tt.port, Service: tt.svc}
		if got := s.Match(target); got != tt.want {
			t.Errorf("%s.Match(port=%d, svc=%q) = %v, want %v", tt.id, tt.port, tt.svc, got, tt.want)
		}
	}
}

func TestTotalScriptCount(t *testing.T) {
	scripts := DefaultEngine.ListScripts()
	// 3 original + 7 extra = 10
	if len(scripts) != 10 {
		t.Errorf("expected 10 registered scripts, got %d: %v", len(scripts), scripts)
	}
}
