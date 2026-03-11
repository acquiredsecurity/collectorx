package target

import (
	"fmt"
	"strings"
)

// ResolvedTarget is a fully resolved, concrete collection target.
type ResolvedTarget struct {
	Name         string // Human-readable name
	Category     string // Grouping (e.g., "EventLogs")
	SourcePath   string // Filesystem path (with KAPE variables)
	FileMask     string // Glob mask for file matching
	Recursive    bool   // Recurse into subdirectories
	AlwaysRaw    bool   // Skip Pass 1, go direct to raw read
	RecreateDirs bool   // Mirror source directory structure
	ParentTarget string // Originating .tkape filename
}

// ResolveTargets resolves one or more target names into a flat, deduplicated list.
func ResolveTargets(names []string, store *TargetStore) ([]ResolvedTarget, error) {
	var all []ResolvedTarget
	seen := make(map[string]bool)

	for _, name := range names {
		visiting := make(map[string]bool)
		resolved, err := resolveTarget(name, store, visiting)
		if err != nil {
			return nil, fmt.Errorf("resolving target %q: %w", name, err)
		}
		for _, t := range resolved {
			key := t.SourcePath + "|" + t.FileMask
			if !seen[key] {
				seen[key] = true
				all = append(all, t)
			}
		}
	}
	return all, nil
}

func resolveTarget(name string, store *TargetStore, visiting map[string]bool) ([]ResolvedTarget, error) {
	canonical := strings.ToLower(name)

	if visiting[canonical] {
		return nil, fmt.Errorf("cycle detected in compound target resolution: %q", name)
	}
	visiting[canonical] = true
	defer delete(visiting, canonical)

	tkape := store.Get(name)
	if tkape == nil {
		return nil, fmt.Errorf("target %q not found in loaded targets", name)
	}

	var resolved []ResolvedTarget

	for _, entry := range tkape.Targets {
		if entry.IsCompound() {
			compoundName := entry.Path
			// Lenient on missing targets, strict on cycles
			if store.Get(compoundName) == nil {
				// Skip unknown compound refs (e.g., disabled .tkape files)
				continue
			}
			children, err := resolveTarget(compoundName, store, visiting)
			if err != nil {
				return nil, fmt.Errorf("resolving compound %q referenced by %q: %w", compoundName, name, err)
			}
			resolved = append(resolved, children...)
		} else {
			resolved = append(resolved, ResolvedTarget{
				Name:         entry.Name,
				Category:     entry.Category,
				SourcePath:   entry.Path,
				FileMask:     entry.FileMask,
				Recursive:    entry.Recursive,
				AlwaysRaw:    entry.AlwaysAddToQueue,
				RecreateDirs: tkape.RecreateDirectories,
				ParentTarget: name,
			})
		}
	}

	return resolved, nil
}
