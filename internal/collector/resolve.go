package collector

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bradleyroughan/forensic-collect/internal/pathresolver"
	"github.com/bradleyroughan/forensic-collect/internal/rawntfs"
	"github.com/bradleyroughan/forensic-collect/internal/target"
)

// ResolveConfig holds parameters for building collection items.
type ResolveConfig struct {
	SourceRoot  string
	TargetNames []string
	Store       *target.TargetStore
	Platform    pathresolver.Platform
	LogWriter   io.Writer
}

// ResolveResult holds the output of item resolution.
type ResolveResult struct {
	Items         []CollectionItem
	UserProfiles  int
	ResolvedCount int
	PreDedupCount int
}

func (cfg *ResolveConfig) logf(format string, args ...any) {
	if cfg.LogWriter != nil {
		fmt.Fprintf(cfg.LogWriter, format, args...)
	}
}

// ResolveCollectionItems resolves targets and expands paths into deduplicated collection items.
func ResolveCollectionItems(cfg ResolveConfig) (*ResolveResult, error) {
	resolved, err := target.ResolveTargets(cfg.TargetNames, cfg.Store)
	if err != nil {
		return nil, err
	}

	cfg.logf("Target resolution: %d concrete targets from %s\n", len(resolved), strings.Join(cfg.TargetNames, ", "))

	// Windows-specific: inject critical targets
	if cfg.Platform == pathresolver.PlatformWindows {
		for _, name := range []string{"NTDS.tkape", "EventTraceLogs.tkape", "AIHistory.tkape", "DefenderLogs.tkape"} {
			if cfg.Store.Get(name) != nil {
				extra, err := target.ResolveTargets([]string{name}, cfg.Store)
				if err == nil {
					resolved = append(resolved, extra...)
				}
			}
		}

		if cfg.Store.Get("NTDS.tkape") == nil {
			resolved = append(resolved,
				target.ResolvedTarget{Name: "NTDS.dit", Category: "ActiveDirectory", SourcePath: `C:\Windows\NTDS`, FileMask: "ntds.dit", AlwaysRaw: true, ParentTarget: "NTDS"},
				target.ResolvedTarget{Name: "NTDS edb logs", Category: "ActiveDirectory", SourcePath: `C:\Windows\NTDS`, FileMask: "edb*", AlwaysRaw: true, ParentTarget: "NTDS"},
				target.ResolvedTarget{Name: "NTDS temp", Category: "ActiveDirectory", SourcePath: `C:\Windows\NTDS`, FileMask: "temp.edb", AlwaysRaw: true, ParentTarget: "NTDS"},
				target.ResolvedTarget{Name: "NTDS schema", Category: "ActiveDirectory", SourcePath: `C:\Windows\NTDS`, FileMask: "schema.ini", ParentTarget: "NTDS"},
			)
		}

		resolved = append(resolved,
			target.ResolvedTarget{Name: "SYSTEM registry hive", Category: "Registry", SourcePath: `C:\Windows\System32\config`, FileMask: "SYSTEM", AlwaysRaw: true, ParentTarget: "RegistryHivesSystem"},
			target.ResolvedTarget{Name: "SOFTWARE registry hive", Category: "Registry", SourcePath: `C:\Windows\System32\config`, FileMask: "SOFTWARE", AlwaysRaw: true, ParentTarget: "RegistryHivesSystem"},
			target.ResolvedTarget{Name: "SECURITY registry hive", Category: "Registry", SourcePath: `C:\Windows\System32\config`, FileMask: "SECURITY", AlwaysRaw: true, ParentTarget: "RegistryHivesSystem"},
			target.ResolvedTarget{Name: "SAM registry hive", Category: "Registry", SourcePath: `C:\Windows\System32\config`, FileMask: "SAM", AlwaysRaw: true, ParentTarget: "RegistryHivesSystem"},
			target.ResolvedTarget{Name: "SYSTEM registry transaction files", Category: "Registry", SourcePath: `C:\Windows\System32\config`, FileMask: "SYSTEM.LOG*", AlwaysRaw: true, ParentTarget: "RegistryHivesSystem"},
			target.ResolvedTarget{Name: "SOFTWARE registry transaction files", Category: "Registry", SourcePath: `C:\Windows\System32\config`, FileMask: "SOFTWARE.LOG*", AlwaysRaw: true, ParentTarget: "RegistryHivesSystem"},
			target.ResolvedTarget{Name: "SECURITY registry transaction files", Category: "Registry", SourcePath: `C:\Windows\System32\config`, FileMask: "SECURITY.LOG*", AlwaysRaw: true, ParentTarget: "RegistryHivesSystem"},
			target.ResolvedTarget{Name: "SAM registry transaction files", Category: "Registry", SourcePath: `C:\Windows\System32\config`, FileMask: "SAM.LOG*", AlwaysRaw: true, ParentTarget: "RegistryHivesSystem"},
		)
	}

	resolvedCount := len(resolved)

	sourceRoot := cfg.SourceRoot
	if resolved, err := filepath.EvalSymlinks(sourceRoot); err == nil {
		sourceRoot = resolved
	}

	pr := pathresolver.NewFromSourceRoot(sourceRoot, cfg.Platform)
	var items []CollectionItem

	// On Windows: open raw NTFS reader FIRST — this is the PRIMARY enumeration method
	var ntfsReader *rawntfs.Reader
	useNTFS := cfg.Platform == pathresolver.PlatformWindows && rawntfs.Available()

	if useNTFS {
		volumeLetter := detectVolumeLetter(sourceRoot)
		if volumeLetter != "" {
			var err error
			ntfsReader, err = rawntfs.Open(volumeLetter)
			if err != nil {
				cfg.logf("WARN: raw NTFS open failed: %v — falling back to OS APIs\n", err)
				useNTFS = false
			} else {
				cfg.logf("Raw NTFS volume ready — using NTFS enumeration as primary method\n")
			}
		} else {
			cfg.logf("WARN: cannot determine volume letter — falling back to OS APIs\n")
			useNTFS = false
		}
	}
	defer func() {
		if ntfsReader != nil {
			ntfsReader.Close()
		}
	}()

	for _, rt := range resolved {
		for _, kapePath := range pr.Expand(rt.SourcePath) {
			localBase := RebasePath(kapePath, sourceRoot, cfg.Platform)

			var matches []string

			if useNTFS {
				// PRIMARY: Raw NTFS enumeration — like Velociraptor
				winPath := toWindowsPath(localBase, sourceRoot)

				// For literal filenames (no wildcards), construct path directly
				if !strings.Contains(rt.FileMask, "*") && !strings.Contains(rt.FileMask, "?") {
					directPath := filepath.Join(localBase, rt.FileMask)
					matches = []string{directPath}
					cfg.logf("  [NTFS] %s -> %s\n", rt.Name, directPath)
				} else {
					// Use NTFS directory enumeration for wildcard masks
					var ntfsEntries []rawntfs.FileEntry
					var ntfsErr error
					if rt.Recursive {
						ntfsEntries, ntfsErr = ntfsReader.ListDirectoryRecursive(winPath, rt.FileMask)
					} else {
						ntfsEntries, ntfsErr = ntfsReader.ListDirectory(winPath, rt.FileMask)
					}

					if ntfsErr == nil {
						for _, entry := range ntfsEntries {
							if !entry.IsDir {
								localPath := RebasePath(entry.FullPath, sourceRoot, cfg.Platform)
								matches = append(matches, localPath)
							}
						}
						if len(matches) > 0 {
							cfg.logf("  [NTFS] %s: %d files in %s\n", rt.Name, len(matches), winPath)
						}
					} else {
						cfg.logf("  [NTFS-FAIL] %s: %v — trying OS glob\n", rt.Name, ntfsErr)
					}

					// Fallback to OS glob if NTFS enumeration failed or returned nothing
					if len(matches) == 0 {
						pattern := filepath.Join(localBase, rt.FileMask)
						matches, _ = filepath.Glob(pattern)
						if len(matches) == 0 {
							matches = CaseInsensitiveGlob(localBase, rt.FileMask, rt.Recursive)
						}
						if len(matches) > 0 {
							cfg.logf("  [OS-GLOB] %s: %d files (NTFS missed, glob found)\n", rt.Name, len(matches))
						}
					}
				}
			} else {
				// Non-Windows or NTFS not available: OS glob only
				if rt.Recursive {
					matches = RecursiveGlob(localBase, rt.FileMask)
				} else {
					pattern := filepath.Join(localBase, rt.FileMask)
					matches, _ = filepath.Glob(pattern)
					if len(matches) == 0 {
						matches = CaseInsensitiveGlob(localBase, rt.FileMask, false)
					}
				}
			}

			if len(matches) == 0 {
				cfg.logf("  [MISS] %s: nothing in %s (mask: %s)\n", rt.Name, localBase, rt.FileMask)
			}

			for _, match := range matches {
				realMatch := match
				dir := filepath.Dir(match)
				if realDir, err := filepath.EvalSymlinks(dir); err == nil && realDir != dir {
					realMatch = filepath.Join(realDir, filepath.Base(match))
				}

				rel, err := filepath.Rel(sourceRoot, realMatch)
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

	// Filter out "Documents and Settings" on modern Windows
	if cfg.Platform == pathresolver.PlatformWindows {
		usersDir := filepath.Join(cfg.SourceRoot, "Users")
		if info, err := os.Stat(usersDir); err == nil && info.IsDir() {
			filtered := items[:0]
			for _, item := range items {
				if !strings.Contains(strings.ToLower(item.SourcePath), "documents and settings") {
					filtered = append(filtered, item)
				}
			}
			items = filtered
		}
	}

	preDedupCount := len(items)

	caseSensitive := cfg.Platform != pathresolver.PlatformWindows
	seen := make(map[string]bool)
	deduped := make([]CollectionItem, 0, len(items))
	for _, item := range items {
		key := item.SourcePath
		if !caseSensitive {
			key = strings.ToLower(key)
		}
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, item)
		}
	}

	cfg.logf("Resolution: %d targets -> %d files (%d before dedup)\n", resolvedCount, len(deduped), preDedupCount)

	return &ResolveResult{
		Items:         deduped,
		UserProfiles:  len(pr.UserProfiles()),
		ResolvedCount: resolvedCount,
		PreDedupCount: preDedupCount,
	}, nil
}

func toWindowsPath(localPath, sourceRoot string) string {
	rel, err := filepath.Rel(sourceRoot, localPath)
	if err != nil {
		return localPath
	}
	driveLetter := ""
	if len(sourceRoot) >= 2 && sourceRoot[1] == ':' {
		driveLetter = sourceRoot[:2]
	}
	return driveLetter + "\\" + strings.ReplaceAll(rel, "/", "\\")
}

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
