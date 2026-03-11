// Package collector implements the forensic file collection engine.
package collector

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bradleyroughan/forensic-collect/internal/rawntfs"
	"github.com/bradleyroughan/forensic-collect/internal/vss"
)

// CollectionItem is a single file queued for collection.
type CollectionItem struct {
	SourcePath  string // Full source path on target system
	DestRelPath string // Relative path within output container
	TargetName  string // Which target this file belongs to
	Category    string // Category from the .tkape target
	ForceRaw    bool   // Skip Pass 1, go directly to raw NTFS
}

// CollectionStats holds aggregate statistics.
type CollectionStats struct {
	FilesCollected uint64
	FilesFailed    uint64
	BytesCollected uint64
	Pass1Count     uint64 // Normal copy
	Pass2Count     uint64 // Raw NTFS
	Pass3Count     uint64 // VSS (last resort)
}

// CollectedFile is the result for a single collected file.
type CollectedFile struct {
	Item     CollectionItem
	Bytes    uint64
	Method   string // "NormalCopy", "RawNTFS", or "VSS"
	DestPath string
}

// ProgressEvent is emitted during collection for real-time progress tracking.
type ProgressEvent struct {
	Phase      string  `json:"phase"`      // "pass1", "pass2", "pass3", "zip"
	Current    int     `json:"current"`
	Total      int     `json:"total"`
	Percent    float64 `json:"percent"`
	File       string  `json:"file,omitempty"`
	Message    string  `json:"message,omitempty"`
	BytesSoFar uint64  `json:"bytesSoFar"`
}

// ProgressCallback is called during collection to report progress.
type ProgressCallback func(event ProgressEvent)

// Engine orchestrates the collection.
type Engine struct {
	SourceRoot  string
	StagingDir  string
	MaxFileSize uint64    // 0 = unlimited
	UseVSS      bool      // Enable VSS as last-resort fallback
	LogWriter   io.Writer // stdout + log file tee (defaults to os.Stdout)
	ErrWriter   io.Writer // stderr + log file tee (defaults to os.Stderr)
	OnProgress  ProgressCallback // optional callback for real-time progress
}

// NewEngine creates a collection engine.
func NewEngine(sourceRoot, stagingDir string) *Engine {
	return &Engine{
		SourceRoot: sourceRoot,
		StagingDir: stagingDir,
		UseVSS:     true,
		LogWriter:  os.Stdout,
		ErrWriter:  os.Stderr,
	}
}

func (e *Engine) logf(format string, args ...any) {
	fmt.Fprintf(e.LogWriter, format, args...)
}

func (e *Engine) logErrf(format string, args ...any) {
	fmt.Fprintf(e.ErrWriter, format, args...)
}

func (e *Engine) progress(evt ProgressEvent) {
	if e.OnProgress != nil {
		e.OnProgress(evt)
	}
}

// Collect executes the three-pass collection strategy.
// Pass 1: Normal copy (fast, works for unlocked files)
// Pass 2: Raw NTFS (reads directly from volume — handles locked files and NTFS metafiles)
// Pass 3: VSS shadow copy (last resort if raw NTFS also fails)
func (e *Engine) Collect(items []CollectionItem) ([]CollectedFile, CollectionStats) {
	var stats CollectionStats
	var collected []CollectedFile
	var failedItems []CollectionItem

	// PASS 1: Normal copy
	totalItems := len(items)
	for i, item := range items {
		e.progress(ProgressEvent{
			Phase: "pass1", Current: i + 1, Total: totalItems,
			Percent: float64(i+1) / float64(totalItems) * 100,
			File: item.SourcePath, BytesSoFar: stats.BytesCollected,
		})
		// Skip directories
		info, err := os.Stat(item.SourcePath)
		if err != nil {
			// Can't stat — might be locked or NTFS metafile, queue for raw NTFS
			failedItems = append(failedItems, item)
			continue
		}
		if info.IsDir() {
			continue
		}

		// Check file size limit
		if e.MaxFileSize > 0 && uint64(info.Size()) > e.MaxFileSize {
			e.logErrf("WARN: skipping %s (%d bytes exceeds limit)\n", item.SourcePath, info.Size())
			stats.FilesFailed++
			continue
		}

		// Items marked ForceRaw skip straight to raw NTFS
		if item.ForceRaw {
			failedItems = append(failedItems, item)
			continue
		}

		dest := filepath.Join(e.StagingDir, item.DestRelPath)

		bytes, err := copyFile(item.SourcePath, dest)
		if err != nil {
			failedItems = append(failedItems, item)
			continue
		}

		stats.FilesCollected++
		stats.BytesCollected += bytes
		stats.Pass1Count++
		collected = append(collected, CollectedFile{
			Item:     item,
			Bytes:    bytes,
			Method:   "NormalCopy",
			DestPath: dest,
		})
	}

	e.logf("Pass 1 complete: %d files collected, %d queued for raw NTFS\n",
		stats.Pass1Count, len(failedItems))

	// PASS 2: Raw NTFS for locked files and metafiles
	var vssItems []CollectionItem
	if len(failedItems) > 0 && rawntfs.Available() {
		rawCollected, rawStats, remaining := e.collectRawNTFS(failedItems)
		collected = append(collected, rawCollected...)
		stats.FilesCollected += rawStats.FilesCollected
		stats.BytesCollected += rawStats.BytesCollected
		stats.Pass2Count = rawStats.FilesCollected
		vssItems = remaining
	} else if len(failedItems) > 0 {
		// Raw NTFS not available (non-Windows), all failures go to VSS
		vssItems = failedItems
	}

	// PASS 3: VSS shadow copy (last resort)
	if len(vssItems) > 0 && e.UseVSS && vss.Available() {
		vssCollected, vssStats := e.collectVSS(vssItems)
		collected = append(collected, vssCollected...)
		stats.FilesCollected += vssStats.FilesCollected
		stats.FilesFailed += vssStats.FilesFailed
		stats.BytesCollected += vssStats.BytesCollected
		stats.Pass3Count = vssStats.FilesCollected
	} else if len(vssItems) > 0 {
		// Nothing more we can do
		for _, item := range vssItems {
			e.logErrf("WARN: could not collect %s (all methods failed)\n", item.SourcePath)
		}
		stats.FilesFailed += uint64(len(vssItems))
	}

	return collected, stats
}

// collectRawNTFS opens the raw volume and copies locked files directly from NTFS.
// Returns collected files, stats, and any items that failed (for VSS fallback).
func (e *Engine) collectRawNTFS(items []CollectionItem) ([]CollectedFile, CollectionStats, []CollectionItem) {
	var stats CollectionStats
	var collected []CollectedFile
	var remaining []CollectionItem

	volumeLetter := detectVolumeLetter(e.SourceRoot)
	if volumeLetter == "" {
		e.logErrf("ERROR: cannot determine volume letter for raw NTFS from %s\n", e.SourceRoot)
		return collected, stats, items // all items go to VSS
	}

	e.logf("Opening raw NTFS volume %s:\\ ...\n", volumeLetter)
	reader, err := rawntfs.Open(volumeLetter)
	if err != nil {
		e.logErrf("ERROR: raw NTFS open failed: %v\n", err)
		return collected, stats, items // all items go to VSS
	}
	defer reader.Close()

	e.logf("Raw NTFS volume opened — reading %d locked files\n", len(items))

	for i, item := range items {
		e.progress(ProgressEvent{
			Phase: "pass2", Current: i + 1, Total: len(items),
			Percent: float64(i+1) / float64(len(items)) * 100,
			File: item.SourcePath, BytesSoFar: stats.BytesCollected,
		})
		dest := filepath.Join(e.StagingDir, item.DestRelPath)

		bytes, err := reader.CopyFile(item.SourcePath, dest)
		if err != nil {
			e.logErrf("WARN: raw NTFS read failed for %s: %v\n", item.SourcePath, err)
			remaining = append(remaining, item) // queue for VSS
			continue
		}

		stats.FilesCollected++
		stats.BytesCollected += bytes
		collected = append(collected, CollectedFile{
			Item:     item,
			Bytes:    bytes,
			Method:   "RawNTFS",
			DestPath: dest,
		})
	}

	e.logf("Pass 2 (raw NTFS) complete: %d files collected, %d queued for VSS\n",
		stats.FilesCollected, len(remaining))

	return collected, stats, remaining
}

// collectVSS creates a VSS snapshot and copies files from it (last resort).
func (e *Engine) collectVSS(items []CollectionItem) ([]CollectedFile, CollectionStats) {
	var stats CollectionStats
	var collected []CollectedFile

	volumeLetter := detectVolumeLetter(e.SourceRoot)
	if volumeLetter == "" {
		e.logErrf("ERROR: cannot determine volume letter for VSS from %s\n", e.SourceRoot)
		stats.FilesFailed = uint64(len(items))
		return collected, stats
	}

	e.logf("Creating VSS snapshot for %s:\\ (last resort)...\n", volumeLetter)
	snapshot, err := vss.CreateSnapshot(volumeLetter)
	if err != nil {
		e.logErrf("ERROR: VSS snapshot creation failed: %v\n", err)
		stats.FilesFailed = uint64(len(items))
		return collected, stats
	}
	defer func() {
		e.logf("Cleaning up VSS snapshot...\n")
		if err := snapshot.Delete(); err != nil {
			e.logErrf("WARN: failed to delete VSS snapshot: %v\n", err)
		}
	}()

	e.logf("VSS snapshot created: %s\n", snapshot.DevicePath)

	for i, item := range items {
		e.progress(ProgressEvent{
			Phase: "pass3", Current: i + 1, Total: len(items),
			Percent: float64(i+1) / float64(len(items)) * 100,
			File: item.SourcePath, BytesSoFar: stats.BytesCollected,
		})
		vssPath := snapshot.FilePath(item.SourcePath)
		dest := filepath.Join(e.StagingDir, item.DestRelPath)

		bytes, err := copyFile(vssPath, dest)
		if err != nil {
			e.logErrf("WARN: VSS copy failed for %s: %v\n", item.SourcePath, err)
			stats.FilesFailed++
			continue
		}

		stats.FilesCollected++
		stats.BytesCollected += bytes
		collected = append(collected, CollectedFile{
			Item:     item,
			Bytes:    bytes,
			Method:   "VSS",
			DestPath: dest,
		})
	}

	e.logf("Pass 3 (VSS) complete: %d files collected, %d failed\n",
		stats.FilesCollected, stats.FilesFailed)

	return collected, stats
}

// detectVolumeLetter extracts the volume letter from a path.
func detectVolumeLetter(path string) string {
	if len(path) >= 2 && isAlpha(path[0]) && path[1] == ':' {
		return string(path[0])
	}
	return ""
}

func copyFile(src, dst string) (uint64, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return 0, fmt.Errorf("creating dir: %w", err)
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return 0, fmt.Errorf("opening source: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return 0, fmt.Errorf("creating dest: %w", err)
	}
	defer dstFile.Close()

	n, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return 0, fmt.Errorf("copying: %w", err)
	}

	return uint64(n), nil
}

// RebasePath converts a KAPE-style Windows path onto a local source root.
func RebasePath(kapePath, sourceRoot string) string {
	relative := kapePath
	if len(kapePath) >= 2 && isAlpha(kapePath[0]) && kapePath[1] == ':' {
		relative = kapePath[2:]
	}
	relative = strings.TrimLeft(relative, "\\/")
	relative = strings.ReplaceAll(relative, "\\", "/")

	if relative == "" {
		return sourceRoot
	}
	return filepath.Join(sourceRoot, relative)
}

func isAlpha(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}
