// Package target handles parsing KAPE .tkape YAML target definition files.
package target

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// TkapeTarget represents a parsed .tkape file.
type TkapeTarget struct {
	Description          string        `yaml:"Description"`
	Author               string        `yaml:"Author"`
	Version              float32       `yaml:"Version"`
	ID                   string        `yaml:"Id"`
	RecreateDirectories  bool          `yaml:"RecreateDirectories"`
	Targets              []TargetEntry `yaml:"Targets"`
	Filename             string        `yaml:"-"` // Original filename on disk
}

// TargetEntry is a single target within a .tkape file.
type TargetEntry struct {
	Name             string `yaml:"Name"`
	Category         string `yaml:"Category"`
	Path             string `yaml:"Path"`
	FileMask         string `yaml:"FileMask"`
	Recursive        bool   `yaml:"Recursive"`
	AlwaysAddToQueue bool   `yaml:"AlwaysAddToQueue"`
	Comment          string `yaml:"Comment"`
}

// IsCompound returns true if this entry references another .tkape file.
func (e *TargetEntry) IsCompound() bool {
	return strings.HasSuffix(e.Path, ".tkape")
}

// TargetStore holds all loaded .tkape targets, keyed by filename.
type TargetStore struct {
	targets map[string]*TkapeTarget
}

// NewTargetStore creates an empty store.
func NewTargetStore() *TargetStore {
	return &TargetStore{targets: make(map[string]*TkapeTarget)}
}

// Get returns a target by filename (e.g., "EventLogs.tkape").
// Lookup is case-insensitive to match KAPE behavior.
func (s *TargetStore) Get(name string) *TkapeTarget {
	return s.targets[strings.ToLower(name)]
}

// Len returns the number of loaded targets.
func (s *TargetStore) Len() int {
	return len(s.targets)
}

// All returns an iterator-style map of all targets.
func (s *TargetStore) All() map[string]*TkapeTarget {
	return s.targets
}

// LoadTargetsFromDir walks a directory tree and loads all .tkape files.
func LoadTargetsFromDir(dir string) (*TargetStore, error) {
	store := NewTargetStore()

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible entries
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".tkape") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: cannot read %s: %v\n", path, err)
			return nil
		}

		var t TkapeTarget
		if err := yaml.Unmarshal(data, &t); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: cannot parse %s: %v\n", path, err)
			return nil
		}

		// Default FileMask to "*" if empty
		for i := range t.Targets {
			if t.Targets[i].FileMask == "" {
				t.Targets[i].FileMask = "*"
			}
		}

		t.Filename = info.Name()
		store.targets[strings.ToLower(info.Name())] = &t
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking targets dir: %w", err)
	}

	return store, nil
}
