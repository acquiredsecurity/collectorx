//go:build windows

package rawntfs

import (
	"path/filepath"
	"strings"

	"www.velocidex.com/golang/go-ntfs/parser"
)

// FileEntry represents a file found via raw NTFS directory enumeration.
type FileEntry struct {
	Name     string
	FullPath string // Windows-style path (C:\Windows\System32\config\SYSTEM)
	IsDir    bool
	Size     int64
}

// ListDirectory enumerates files in a directory using raw NTFS MFT parsing.
// This bypasses OS-level APIs entirely — works even when os.ReadDir fails
// on locked/protected directories like C:\Windows\System32\config\.
//
// dirPath is a Windows path like "C:\Windows\System32\config"
// mask is a glob pattern like "*.evtx" or "SYSTEM" (empty = all files)
func (r *Reader) ListDirectory(dirPath string, mask string) ([]FileEntry, error) {
	ntfsPath := toNTFSPath(dirPath)

	// Get root MFT entry (entry 5 = root directory)
	root, err := r.ntfsCtx.GetMFT(5)
	if err != nil {
		return nil, err
	}

	// Navigate to the target directory
	dir, err := root.Open(r.ntfsCtx, ntfsPath)
	if err != nil {
		return nil, err
	}

	// Enumerate directory entries from MFT
	var entries []FileEntry

	for _, info := range parser.ListDir(r.ntfsCtx, dir) {
		name := info.Name
		if name == "." || name == ".." || name == "" {
			continue
		}

		// Apply mask filter
		if mask != "" {
			matched, _ := filepath.Match(strings.ToLower(mask), strings.ToLower(name))
			if !matched {
				continue
			}
		}

		// Reconstruct Windows-style full path
		driveLetter := ""
		if len(dirPath) >= 2 && dirPath[1] == ':' {
			driveLetter = dirPath[:2]
		}
		fullPath := driveLetter + "\\" + strings.ReplaceAll(ntfsPath, "/", "\\") + "\\" + name

		entries = append(entries, FileEntry{
			Name:     name,
			FullPath: fullPath,
			IsDir:    info.IsDir,
			Size:     info.Size,
		})
	}

	return entries, nil
}

// ListDirectoryRecursive enumerates files recursively using raw NTFS.
// mask is applied to files only, not directories.
func (r *Reader) ListDirectoryRecursive(dirPath string, mask string) ([]FileEntry, error) {
	var results []FileEntry

	entries, err := r.ListDirectory(dirPath, "")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir {
			subEntries, err := r.ListDirectoryRecursive(entry.FullPath, mask)
			if err == nil {
				results = append(results, subEntries...)
			}
		} else {
			if mask != "" {
				matched, _ := filepath.Match(strings.ToLower(mask), strings.ToLower(entry.Name))
				if !matched {
					continue
				}
			}
			results = append(results, entry)
		}
	}

	return results, nil
}
