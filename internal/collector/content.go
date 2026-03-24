package collector

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ContentFilter defines a file-path-based content collection filter (robocopy-style).
type ContentFilter struct {
	SearchPath    string   // Root path to search (e.g., C:\Users)
	FileFilters   []string // Glob patterns (e.g., "*.zip", "*.docx")
	ExcludePaths  []string // Glob patterns to exclude (e.g., "AppData\Local\*")
	MaxDepth      int      // 0 = unlimited
	MinSize       uint64   // 0 = no minimum
	MaxSize       uint64   // 0 = no maximum
	ModifiedAfter *time.Time
	ModifiedBefore *time.Time
	PresetName    string   // If populated, identifies which preset matched
}

// ContentPresets returns the built-in content collection presets.
func ContentPresets() map[string]ContentFilter {
	return map[string]ContentFilter{
		"recycle-bin": {
			SearchPath:  `C:\$Recycle.Bin`,
			FileFilters: []string{"*"},
			PresetName:  "recycle-bin",
		},
		"user-documents": {
			SearchPath:  `C:\Users`,
			FileFilters: []string{"*"},
			ExcludePaths: []string{
				"AppData",
			},
			PresetName: "user-documents",
		},
		"archives": {
			SearchPath:  `C:\Users`,
			FileFilters: []string{"*.zip", "*.rar", "*.7z", "*.tar", "*.gz", "*.tar.gz", "*.tgz"},
			PresetName:  "archives",
		},
		"office-docs": {
			SearchPath:  `C:\Users`,
			FileFilters: []string{"*.docx", "*.xlsx", "*.pptx", "*.pdf", "*.doc", "*.xls", "*.ppt"},
			PresetName:  "office-docs",
		},
		"email-stores": {
			SearchPath:  `C:\Users`,
			FileFilters: []string{"*.pst", "*.ost", "*.mbox", "*.eml"},
			PresetName:  "email-stores",
		},
		"databases": {
			SearchPath:  `C:\Users`,
			FileFilters: []string{"*.sqlite", "*.db", "*.mdb", "*.accdb"},
			PresetName:  "databases",
		},
		"scripts": {
			SearchPath:  `C:\Users`,
			FileFilters: []string{"*.ps1", "*.bat", "*.cmd", "*.vbs", "*.js", "*.py", "*.sh"},
			PresetName:  "scripts",
		},
	}
}

// ResolveContentFilter expands a content filter into collection items by walking the search path.
func ResolveContentFilter(filter ContentFilter, sourceRoot string) []CollectionItem {
	var items []CollectionItem

	// Resolve symlinks in source root (e.g. macOS /tmp -> /private/tmp)
	if resolved, err := filepath.EvalSymlinks(sourceRoot); err == nil {
		sourceRoot = resolved
	}

	searchPath := filter.SearchPath
	// If the search path already exists on disk, use it directly (user provided full path)
	if info, err := os.Stat(searchPath); err == nil && info.IsDir() {
		// Already a valid directory — resolve symlinks for consistent filepath.Rel
		if resolved, err := filepath.EvalSymlinks(searchPath); err == nil {
			searchPath = resolved
		}
	} else if len(searchPath) >= 2 && isAlpha(searchPath[0]) && searchPath[1] == ':' {
		// Windows drive letter path — rebase to source root
		relative := searchPath[2:]
		relative = strings.TrimLeft(relative, "\\/")
		relative = strings.ReplaceAll(relative, "\\", "/")
		searchPath = filepath.Join(sourceRoot, relative)
	} else if strings.HasPrefix(searchPath, "/") {
		// Unix absolute path — rebase to source root
		searchPath = filepath.Join(sourceRoot, strings.TrimLeft(searchPath, "/"))
	}

	currentDepth := func(path string) int {
		rel, err := filepath.Rel(searchPath, path)
		if err != nil {
			return 0
		}
		return strings.Count(rel, string(filepath.Separator))
	}

	filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Max depth check
		if filter.MaxDepth > 0 && currentDepth(path) > filter.MaxDepth {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if info.IsDir() {
			// Check exclude paths
			for _, exc := range filter.ExcludePaths {
				if matchesPathComponent(path, exc) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Check exclude paths for files
		for _, exc := range filter.ExcludePaths {
			if matchesPathComponent(path, exc) {
				return nil
			}
		}

		// Size filters
		size := uint64(info.Size())
		if filter.MinSize > 0 && size < filter.MinSize {
			return nil
		}
		if filter.MaxSize > 0 && size > filter.MaxSize {
			return nil
		}

		// Date filters
		modTime := info.ModTime()
		if filter.ModifiedAfter != nil && modTime.Before(*filter.ModifiedAfter) {
			return nil
		}
		if filter.ModifiedBefore != nil && modTime.After(*filter.ModifiedBefore) {
			return nil
		}

		// File filter matching
		matched := false
		name := strings.ToLower(info.Name())
		for _, pattern := range filter.FileFilters {
			if m, _ := filepath.Match(strings.ToLower(pattern), name); m {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}

		rel, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			rel = path
		}

		targetName := "ContentFilter"
		if filter.PresetName != "" {
			targetName = "ContentFilter:" + filter.PresetName
		}

		items = append(items, CollectionItem{
			SourcePath:  path,
			DestRelPath: filepath.Join("ContentCollection", rel),
			TargetName:  targetName,
			Category:    "ContentCollection",
		})

		return nil
	})

	return items
}

// matchesPathComponent checks if any component of the path matches the pattern.
func matchesPathComponent(fullPath, pattern string) bool {
	components := strings.Split(filepath.ToSlash(fullPath), "/")
	lowerPattern := strings.ToLower(pattern)
	for _, c := range components {
		if m, _ := filepath.Match(lowerPattern, strings.ToLower(c)); m {
			return true
		}
	}
	return false
}

// ParseFileFilters parses a comma-separated file filter string into a slice.
func ParseFileFilters(s string) []string {
	var filters []string
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			filters = append(filters, f)
		}
	}
	return filters
}
