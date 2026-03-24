// Package collector implements the forensic file collection engine.
package collector

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bradleyroughan/forensic-collect/internal/pathresolver"
	"github.com/bradleyroughan/forensic-collect/internal/rawntfs"
	"github.com/bradleyroughan/forensic-collect/internal/vss"
)

// CollectionItem is a single file queued for collection.
type CollectionItem struct {
	SourcePath  string // Full source path on target system
	DestRelPath string // Relative path within output container
	TargetName  string // Which target this file belongs to
	Category    string // Category from the .tkape target
	ForceRaw    bool   // Skip normal copy, go directly to raw NTFS
}

// CollectionStats holds aggregate statistics.
type CollectionStats struct {
	FilesCollected uint64
	FilesFailed    uint64
	BytesCollected uint64
	NormalCount    uint64 // Collected via normal copy
	RawNTFSCount   uint64 // Collected via raw NTFS
	VSSCount       uint64 // Collected via VSS (only with --vss-collect-all)
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
	Phase      string  `json:"phase"`      // "collect", "vss", "zip"
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
	LogWriter   io.Writer // stdout + log file tee (defaults to os.Stdout)
	ErrWriter   io.Writer // stderr + log file tee (defaults to os.Stderr)
	OnProgress  ProgressCallback // optional callback for real-time progress
}

// NewEngine creates a collection engine.
func NewEngine(sourceRoot, stagingDir string) *Engine {
	return &Engine{
		SourceRoot: sourceRoot,
		StagingDir: stagingDir,
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

// Collect executes a single-pass smart collection strategy.
// For each file, it picks the right method upfront:
//   - Known-locked files (registry hives, NTFS metafiles, etc.) → raw NTFS directly
//   - Regular files → normal copy, with raw NTFS fallback on failure
//   - Non-Windows / mounted images → normal copy only (raw NTFS not available)
//
// VSS is NOT used during normal collection. Use CollectVSS separately for
// shadow copy collection (--vss-collect-all).
func (e *Engine) Collect(items []CollectionItem) ([]CollectedFile, CollectionStats) {
	var stats CollectionStats
	var collected []CollectedFile

	// Open raw NTFS reader lazily — only if we actually need it
	var ntfsReader *rawntfs.Reader
	var ntfsOpenErr error
	var ntfsOpened bool

	getNTFSReader := func() (*rawntfs.Reader, error) {
		if ntfsOpened {
			return ntfsReader, ntfsOpenErr
		}
		ntfsOpened = true
		if !rawntfs.Available() {
			ntfsOpenErr = fmt.Errorf("raw NTFS not available on this platform")
			return nil, ntfsOpenErr
		}
		volumeLetter := detectVolumeLetter(e.SourceRoot)
		if volumeLetter == "" {
			ntfsOpenErr = fmt.Errorf("cannot determine volume letter from %s", e.SourceRoot)
			return nil, ntfsOpenErr
		}
		e.logf("Opening raw NTFS volume %s:\\ ...\n", volumeLetter)
		ntfsReader, ntfsOpenErr = rawntfs.Open(volumeLetter)
		if ntfsOpenErr != nil {
			e.logErrf("WARN: raw NTFS open failed: %v (locked files will use normal copy)\n", ntfsOpenErr)
		} else {
			e.logf("Raw NTFS volume ready\n")
		}
		return ntfsReader, ntfsOpenErr
	}
	defer func() {
		if ntfsReader != nil {
			ntfsReader.Close()
		}
	}()

	totalItems := len(items)
	for i, item := range items {
		e.progress(ProgressEvent{
			Phase: "collect", Current: i + 1, Total: totalItems,
			Percent: float64(i+1) / float64(totalItems) * 100,
			File: item.SourcePath, BytesSoFar: stats.BytesCollected,
		})

		// Skip directories and macOS resource forks (._* files)
		base := filepath.Base(item.SourcePath)
		if strings.HasPrefix(base, "._") {
			continue
		}
		info, statErr := os.Stat(item.SourcePath)
		if statErr == nil && info.IsDir() {
			continue
		}

		// Check file size limit (only if we could stat it)
		if statErr == nil && e.MaxFileSize > 0 && uint64(info.Size()) > e.MaxFileSize {
			e.logErrf("WARN: skipping %s (%d bytes exceeds limit)\n", item.SourcePath, info.Size())
			stats.FilesFailed++
			continue
		}

		dest := filepath.Join(e.StagingDir, item.DestRelPath)
		useRawNTFS := item.ForceRaw || isKnownLocked(item.SourcePath)

		// Strategy: pick the right method for each file
		var bytes uint64
		var method string
		var err error

		if useRawNTFS && rawntfs.Available() {
			// Known-locked file → go straight to raw NTFS
			reader, rErr := getNTFSReader()
			if rErr == nil {
				bytes, err = reader.CopyFile(item.SourcePath, dest)
				if err == nil {
					method = "RawNTFS"
				}
			}
			// If raw NTFS failed, fall back to normal copy (might work on mounted images)
			if method == "" {
				bytes, err = copyFile(item.SourcePath, dest)
				if err == nil {
					method = "NormalCopy"
				}
			}
		} else if statErr != nil && rawntfs.Available() {
			// Can't stat (likely locked) → try raw NTFS, then give up
			reader, rErr := getNTFSReader()
			if rErr == nil {
				bytes, err = reader.CopyFile(item.SourcePath, dest)
				if err == nil {
					method = "RawNTFS"
				}
			}
			if method == "" {
				e.logErrf("WARN: could not collect %s (stat failed, raw NTFS failed)\n", item.SourcePath)
				stats.FilesFailed++
				continue
			}
		} else {
			// Regular file → normal copy, fall back to raw NTFS on failure
			bytes, err = copyFile(item.SourcePath, dest)
			if err == nil {
				method = "NormalCopy"
			} else if rawntfs.Available() {
				reader, rErr := getNTFSReader()
				if rErr == nil {
					bytes, err = reader.CopyFile(item.SourcePath, dest)
					if err == nil {
						method = "RawNTFS"
					}
				}
			}
		}

		if method == "" {
			e.logErrf("WARN: could not collect %s: %v\n", item.SourcePath, err)
			stats.FilesFailed++
			continue
		}

		stats.FilesCollected++
		stats.BytesCollected += bytes
		switch method {
		case "NormalCopy":
			stats.NormalCount++
		case "RawNTFS":
			stats.RawNTFSCount++
		}
		collected = append(collected, CollectedFile{
			Item:     item,
			Bytes:    bytes,
			Method:   method,
			DestPath: dest,
		})
	}

	e.logf("Collection complete: %d files (%d normal, %d raw NTFS, %d failed)\n",
		stats.FilesCollected, stats.NormalCount, stats.RawNTFSCount, stats.FilesFailed)

	return collected, stats
}

// CollectVSS collects artifacts from VSS shadow copies.
// This is a separate operation invoked by --vss-collect-all, not part of normal collection.
func (e *Engine) CollectVSS(items []CollectionItem) ([]CollectedFile, CollectionStats) {
	var stats CollectionStats
	var collected []CollectedFile

	if !vss.Available() {
		e.logErrf("WARN: VSS is not available on this platform\n")
		return collected, stats
	}

	volumeLetter := detectVolumeLetter(e.SourceRoot)
	if volumeLetter == "" {
		e.logErrf("ERROR: cannot determine volume letter for VSS from %s\n", e.SourceRoot)
		stats.FilesFailed = uint64(len(items))
		return collected, stats
	}

	e.logf("Creating VSS snapshot for %s:\\ ...\n", volumeLetter)
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
			Phase: "vss", Current: i + 1, Total: len(items),
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
		stats.VSSCount++
		collected = append(collected, CollectedFile{
			Item:     item,
			Bytes:    bytes,
			Method:   "VSS",
			DestPath: dest,
		})
	}

	e.logf("VSS collection complete: %d files collected, %d failed\n",
		stats.FilesCollected, stats.FilesFailed)

	return collected, stats
}

// isKnownLocked returns true for file paths that are known to be locked by
// the Windows OS on a live system. These go straight to raw NTFS instead of
// wasting time on a normal copy that will always fail.
func isKnownLocked(path string) bool {
	// Normalize to lowercase for case-insensitive matching
	lower := strings.ToLower(path)
	// Normalize separators
	lower = strings.ReplaceAll(lower, "\\", "/")

	// NTFS metafiles (always locked, live at volume root)
	base := filepath.Base(lower)
	if strings.HasPrefix(base, "$") {
		return true
	}

	// Registry hives — system
	systemConfigFiles := []string{
		"windows/system32/config/sam",
		"windows/system32/config/system",
		"windows/system32/config/software",
		"windows/system32/config/security",
		"windows/system32/config/default",
		"windows/system32/config/bcd-template",
		"windows/system32/config/components",
		"windows/system32/config/drivers",
		"windows/system32/config/elam",
		"windows/system32/config/userdiff",
		"windows/system32/config/vsmidk",
		"windows/system32/config/bbi",
	}
	for _, pattern := range systemConfigFiles {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Registry hives — user (NTUSER.DAT, UsrClass.dat, and their .LOG files)
	if strings.Contains(lower, "ntuser.dat") {
		return true
	}
	if strings.Contains(lower, "usrclass.dat") {
		return true
	}

	// NTDS.dit (Active Directory database)
	if strings.Contains(lower, "ntds.dit") || strings.Contains(lower, "ntds/") {
		return true
	}

	// SRUM database
	if strings.Contains(lower, "system32/sru/") {
		return true
	}

	// Amcache
	if strings.Contains(lower, "amcache.hve") {
		return true
	}

	// Syscache
	if strings.Contains(lower, "syscache.hve") {
		return true
	}

	// WBEM repository
	if strings.Contains(lower, "system32/wbem/repository/") {
		return true
	}

	// Event logs (commonly locked during active logging)
	if strings.HasSuffix(lower, ".evtx") {
		return true
	}

	// Event trace logs
	if strings.HasSuffix(lower, ".etl") {
		return true
	}

	// BCD (Boot Configuration Data)
	if strings.HasSuffix(lower, "/bcd") && strings.Contains(lower, "boot/") {
		return true
	}

	// pagefile, hiberfil, swapfile
	if strings.Contains(lower, "pagefile.sys") ||
		strings.Contains(lower, "hiberfil.sys") ||
		strings.Contains(lower, "swapfile.sys") {
		return true
	}

	// Windows Timeline / Activity Cache
	if strings.Contains(lower, "activitiescache.db") {
		return true
	}

	// EventTranscript database
	if strings.Contains(lower, "eventtranscript.db") {
		return true
	}

	return false
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

	// Grab source timestamps before copying
	srcInfo, statErr := srcFile.Stat()

	dstFile, err := os.Create(dst)
	if err != nil {
		return 0, fmt.Errorf("creating dest: %w", err)
	}
	defer dstFile.Close()

	n, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return 0, fmt.Errorf("copying: %w", err)
	}

	// Preserve original timestamps (created + modified + accessed) on the copy
	if statErr == nil {
		_ = preserveTimestamps(dst, srcInfo)
	}

	return uint64(n), nil
}

// RebasePath converts a KAPE-style path onto a local source root.
// For Windows: strips drive letter (C:\foo -> sourceRoot/foo)
// For macOS/Linux: strips leading / and prepends sourceRoot (/var/log -> sourceRoot/var/log)
func RebasePath(kapePath, sourceRoot string, platform pathresolver.Platform) string {
	relative := kapePath

	switch platform {
	case pathresolver.PlatformMacOS, pathresolver.PlatformLinux:
		// Unix paths: strip leading / to make relative
		relative = strings.TrimLeft(relative, "/")
	default:
		// Windows paths: strip drive letter
		if len(kapePath) >= 2 && isAlpha(kapePath[0]) && kapePath[1] == ':' {
			relative = kapePath[2:]
		}
		relative = strings.TrimLeft(relative, "\\/")
		relative = strings.ReplaceAll(relative, "\\", "/")
	}

	if relative == "" {
		return sourceRoot
	}
	return filepath.Join(sourceRoot, relative)
}

func isAlpha(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}
