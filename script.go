package gomap

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ScriptCategory represents a script classification (matching nmap categories).
type ScriptCategory string

const (
	CategoryAuth      ScriptCategory = "auth"
	CategoryBroadcast ScriptCategory = "broadcast"
	CategoryDefault   ScriptCategory = "default"
	CategoryDiscovery ScriptCategory = "discovery"
	CategoryDOS       ScriptCategory = "dos"
	CategoryExploit   ScriptCategory = "exploit"
	CategoryExternal  ScriptCategory = "external"
	CategoryFuzzer    ScriptCategory = "fuzzer"
	CategoryIntrusive ScriptCategory = "intrusive"
	CategoryMalware   ScriptCategory = "malware"
	CategorySafe      ScriptCategory = "safe"
	CategoryVersion   ScriptCategory = "version"
	CategoryVuln      ScriptCategory = "vuln"
)

// defaultScriptTimeout is the default per-script network timeout.
const defaultScriptTimeout = 5 * time.Second

// ScriptPhase determines when a script runs.
type ScriptPhase int

const (
	// PhasePreScan runs before any scanning begins.
	PhasePreScan ScriptPhase = iota
	// PhasePort runs against each open port.
	PhasePort
	// PhaseHost runs once per host after port scanning.
	PhaseHost
	// PhasePostScan runs after all scanning is complete.
	PhasePostScan
)

// ScriptTarget provides context to a running script.
type ScriptTarget struct {
	Host    string
	IP      string
	Port    int
	Service string
	Banner  string
	Result  *ScanResult

	// Args provides script arguments from --script-args.
	Args map[string]string

	// Trace enables verbose tracing of script data (--script-trace).
	Trace bool
}

// ScriptOutput contains the results of a script execution.
type ScriptOutput struct {
	ScriptID string
	Output   string
	Elements map[string]string
	Error    error
}

// String returns a formatted script output.
func (so *ScriptOutput) String() string {
	if so.Error != nil {
		return fmt.Sprintf("|_%s: ERROR: %v", so.ScriptID, so.Error)
	}
	if len(so.Elements) > 0 {
		var lines []string
		lines = append(lines, fmt.Sprintf("| %s:", so.ScriptID))
		keys := make([]string, 0, len(so.Elements))
		for k := range so.Elements {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			lines = append(lines, fmt.Sprintf("|   %s: %s", k, so.Elements[k]))
		}
		return strings.Join(lines, "\n")
	}
	return fmt.Sprintf("| %s: %s", so.ScriptID, so.Output)
}

// Script is the interface that all gomap scripts must implement.
type Script interface {
	// ID returns the unique script identifier (e.g., "http-title").
	ID() string

	// Description returns a human-readable description.
	Description() string

	// Categories returns the script's categories.
	Categories() []ScriptCategory

	// Phase returns when the script should run.
	Phase() ScriptPhase

	// Match returns true if this script should run against the given target.
	// For port scripts, this typically checks service name or port number.
	Match(target ScriptTarget) bool

	// Run executes the script against the target.
	Run(ctx context.Context, target ScriptTarget) (*ScriptOutput, error)
}

// ScriptEngine manages script registration, selection, and execution.
type ScriptEngine struct {
	mu      sync.RWMutex
	scripts map[string]Script
}

// NewScriptEngine creates a new script engine.
func NewScriptEngine() *ScriptEngine {
	return &ScriptEngine{
		scripts: make(map[string]Script),
	}
}

// Register adds a script to the engine.
func (e *ScriptEngine) Register(s Script) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.scripts[s.ID()] = s
}

// ListScripts returns all registered script IDs.
func (e *ScriptEngine) ListScripts() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ids := make([]string, 0, len(e.scripts))
	for id := range e.scripts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// GetScript returns a script by ID.
func (e *ScriptEngine) GetScript(id string) (Script, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	s, ok := e.scripts[id]
	return s, ok
}

// SelectByCategory returns all scripts matching any of the given categories.
func (e *ScriptEngine) SelectByCategory(categories ...ScriptCategory) []Script {
	e.mu.RLock()
	defer e.mu.RUnlock()

	catSet := make(map[ScriptCategory]bool, len(categories))
	for _, c := range categories {
		catSet[c] = true
	}

	var result []Script
	for _, s := range e.scripts {
		for _, sc := range s.Categories() {
			if catSet[sc] {
				result = append(result, s)
				break
			}
		}
	}
	return result
}

// SelectByIDs returns scripts matching the given IDs. Supports glob patterns
// with "*" (e.g., "http-*").
func (e *ScriptEngine) SelectByIDs(ids ...string) []Script {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []Script
	for _, pattern := range ids {
		if strings.Contains(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			for _, s := range e.scripts {
				if strings.HasPrefix(s.ID(), prefix) {
					result = append(result, s)
				}
			}
		} else {
			if s, ok := e.scripts[pattern]; ok {
				result = append(result, s)
			}
		}
	}
	return result
}

// RunScripts executes the given scripts against a target with concurrency control.
func (e *ScriptEngine) RunScripts(ctx context.Context, scripts []Script, target ScriptTarget, workers int) []ScriptOutput {
	if workers <= 0 {
		workers = 4
	}

	type job struct {
		script Script
	}

	jobs := make(chan job, len(scripts))
	results := make(chan ScriptOutput, len(scripts))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				if !j.script.Match(target) {
					continue
				}
				out, err := j.script.Run(ctx, target)
				if err != nil {
					results <- ScriptOutput{ScriptID: j.script.ID(), Error: err}
					continue
				}
				if out != nil {
					results <- *out
				}
			}
		}()
	}

	for _, s := range scripts {
		jobs <- job{script: s}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var outputs []ScriptOutput
	for out := range results {
		outputs = append(outputs, out)
	}

	sort.Slice(outputs, func(i, j int) bool {
		return outputs[i].ScriptID < outputs[j].ScriptID
	})

	return outputs
}

// DefaultEngine is the global script engine with built-in scripts.
var DefaultEngine = NewScriptEngine()

func init() {
	// Register built-in scripts
	DefaultEngine.Register(&httpTitleScript{})
	DefaultEngine.Register(&sshHostKeyScript{})
	DefaultEngine.Register(&sslCertScript{})
}
