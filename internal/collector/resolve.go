package collector

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/bradleyroughan/forensic-collect/internal/pathresolver"
	"github.com/bradleyroughan/forensic-collect/internal/target"
)

// ResolveConfig holds parameters for building collection items.
type ResolveConfig struct {
	SourceRoot  string
	TargetNames []string
	Store       *target.TargetStore
}

// ResolveResult holds the output of item resolution.
type ResolveResult struct {
	Items         []CollectionItem
	UserProfiles  int
	ResolvedCount int
	PreDedupCount int
}

// ResolveCollectionItems resolves targets and expands paths into deduplicated collection items.
// This is the shared logic used by both the CLI and the web server.
func ResolveCollectionItems(cfg ResolveConfig) (*ResolveResult, error) {
	resolved, err := target.ResolveTargets(cfg.TargetNames, cfg.Store)
	if err != nil {
		return nil, err
	}

	// Extra targets for AS-Tools parsers that KapeTriage may not cover
	for _, name := range []string{"NTDS.tkape", "EventTraceLogs.tkape", "AIHistory.tkape", "DefenderLogs.tkape"} {
		if cfg.Store.Get(name) != nil {
			extra, err := target.ResolveTargets([]string{name}, cfg.Store)
			if err == nil {
				resolved = append(resolved, extra...)
			}
		}
	}

	// Inject NTDS inline if no .tkape file was found
	if cfg.Store.Get("NTDS.tkape") == nil {
		resolved = append(resolved,
			target.ResolvedTarget{Name: "NTDS.dit", Category: "ActiveDirectory", SourcePath: `C:\Windows\NTDS`, FileMask: "ntds.dit", AlwaysRaw: true, ParentTarget: "NTDS"},
			target.ResolvedTarget{Name: "NTDS edb logs", Category: "ActiveDirectory", SourcePath: `C:\Windows\NTDS`, FileMask: "edb*", AlwaysRaw: true, ParentTarget: "NTDS"},
			target.ResolvedTarget{Name: "NTDS temp", Category: "ActiveDirectory", SourcePath: `C:\Windows\NTDS`, FileMask: "temp.edb", AlwaysRaw: true, ParentTarget: "NTDS"},
			target.ResolvedTarget{Name: "NTDS schema", Category: "ActiveDirectory", SourcePath: `C:\Windows\NTDS`, FileMask: "schema.ini", ParentTarget: "NTDS"},
		)
	}

	resolvedCount := len(resolved)

	// Expand paths using path resolver
	pr := pathresolver.NewFromSourceRoot(cfg.SourceRoot)
	var items []CollectionItem

	for _, rt := range resolved {
		for _, kapePath := range pr.Expand(rt.SourcePath) {
			localBase := RebasePath(kapePath, cfg.SourceRoot)

			var matches []string
			if rt.Recursive {
				matches = RecursiveGlob(localBase, rt.FileMask)
			} else {
				pattern := filepath.Join(localBase, rt.FileMask)
				matches, _ = filepath.Glob(pattern)
				if len(matches) == 0 {
					matches = CaseInsensitiveGlob(localBase, rt.FileMask, false)
				}
			}

			for _, match := range matches {
				// Resolve junctions (e.g., Documents and Settings -> Users)
				realMatch := match
				dir := filepath.Dir(match)
				if realDir, err := filepath.EvalSymlinks(dir); err == nil && realDir != dir {
					realMatch = filepath.Join(realDir, filepath.Base(match))
				}

				rel, err := filepath.Rel(cfg.SourceRoot, realMatch)
				if err != nil {
					rel = realMatch
				}

				items = append(items, CollectionItem{
					SourcePath:  realMatch,
					DestRelPath: filepath.Join(rt.Category, rel),
					TargetName:  rt.Name,
					Category:    rt.Category,
					ForceRaw:    rt.AlwaysRaw,
				})
			}
		}
	}

	preDedupCount := len(items)

	// Deduplicate by source path (case-insensitive for Windows compatibility)
	seen := make(map[string]bool)
	deduped := make([]CollectionItem, 0, len(items))
	for _, item := range items {
		key := strings.ToLower(item.SourcePath)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, item)
		}
	}

	return &ResolveResult{
		Items:         deduped,
		UserProfiles:  len(pr.UserProfiles()),
		ResolvedCount: resolvedCount,
		PreDedupCount: preDedupCount,
	}, nil
}

// RecursiveGlob walks a directory tree and returns files matching the mask (case-insensitive).
func RecursiveGlob(root, mask string) []string {
	var matches []string
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		matched, _ := filepath.Match(strings.ToLower(mask), strings.ToLower(info.Name()))
		if matched {
			matches = append(matches, path)
		}
		return nil
	})
	return matches
}

// CaseInsensitiveGlob performs a case-insensitive glob match in a directory.
func CaseInsensitiveGlob(dir, mask string, recursive bool) []string {
	var matches []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if entry.IsDir() {
			if recursive {
				matches = append(matches, CaseInsensitiveGlob(filepath.Join(dir, entry.Name()), mask, true)...)
			}
			continue
		}
		matched, _ := filepath.Match(strings.ToLower(mask), strings.ToLower(entry.Name()))
		if matched {
			matches = append(matches, filepath.Join(dir, entry.Name()))
		}
	}
	return matches
}
