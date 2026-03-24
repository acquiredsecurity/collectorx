// Package output handles ZIP archive creation with manifest and hashing.
package output

import (
	"archive/zip"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/klauspost/compress/flate"
)

// Manifest is the collection manifest included in the ZIP.
type Manifest struct {
	CollectionID    string          `json:"collection_id"`
	Hostname        string          `json:"hostname"`
	Platform        string          `json:"platform"`
	CollectionStart time.Time       `json:"collection_start"`
	CollectionEnd   *time.Time      `json:"collection_end"`
	ToolVersion     string          `json:"tool_version"`
	OutputFormat    string          `json:"output_format"`
	Operator        string          `json:"operator,omitempty"`
	CaseNumber      string          `json:"case_number,omitempty"`
	TargetsUsed     []string        `json:"targets_used"`
	Files           []ManifestEntry `json:"files"`
	Stats           ManifestStats   `json:"stats"`
}

// ManifestEntry records details about a single collected file.
type ManifestEntry struct {
	SourcePath      string `json:"source_path"`
	DestPath        string `json:"dest_path"`
	SizeBytes       uint64 `json:"size_bytes"`
	MD5             string `json:"md5"`
	SHA256          string `json:"sha256"`
	CollectedVia    string `json:"collected_via"`
	TargetName      string `json:"target_name"`
	FilterMatched   string `json:"filter_matched,omitempty"`
	VSSSnapshotID   string `json:"vss_snapshot_id,omitempty"`
	VSSSnapshotDate string `json:"vss_snapshot_date,omitempty"`
}

// ManifestStats holds aggregate statistics.
type ManifestStats struct {
	TotalFiles   uint64 `json:"total_files"`
	TotalBytes   uint64 `json:"total_bytes"`
	NormalFiles  uint64 `json:"normal_copy_files"`
	RawNTFSFiles uint64 `json:"raw_ntfs_files"`
	VSSFiles     uint64 `json:"vss_files,omitempty"`
	FailedFiles  uint64 `json:"failed_files"`
}

// EvidenceWriter streams files into a ZIP archive while computing hashes.
type EvidenceWriter struct {
	zipWriter *zip.Writer
	manifest  *Manifest
}

// FileHashes holds computed hashes for a single file.
type FileHashes struct {
	MD5       string
	SHA256    string
	SizeBytes uint64
}

// NewEvidenceWriter creates a new ZIP evidence writer.
func NewEvidenceWriter(w io.Writer, hostname string, targets []string) *EvidenceWriter {
	zw := zip.NewWriter(w)
	// Use best compression (Deflate level 9)
	zw.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestCompression)
	})

	return &EvidenceWriter{
		zipWriter: zw,
		manifest: &Manifest{
			CollectionID:    generateID(),
			Hostname:        hostname,
			CollectionStart: time.Now().UTC(),
			ToolVersion:     "0.1.0",
			TargetsUsed:     targets,
		},
	}
}

// AddFile adds a file to the ZIP from disk, computing hashes simultaneously.
// Preserves the source file's modification time in the ZIP entry.
func (ew *EvidenceWriter) AddFile(zipPath string, diskPath string) (*FileHashes, error) {
	src, err := os.Open(diskPath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", diskPath, err)
	}
	defer src.Close()

	// Use source file's modification time, not current time
	var modTime time.Time
	if info, err := src.Stat(); err == nil {
		modTime = info.ModTime()
	}

	return ew.addFileFromReaderWithTime(zipPath, src, modTime)
}

// AddFileFromReader adds a file to the ZIP from a reader (uses current time).
func (ew *EvidenceWriter) AddFileFromReader(zipPath string, r io.Reader) (*FileHashes, error) {
	return ew.addFileFromReaderWithTime(zipPath, r, time.Now())
}

// addFileFromReaderWithTime adds a file to the ZIP with a specific modification time.
func (ew *EvidenceWriter) addFileFromReaderWithTime(zipPath string, r io.Reader, modTime time.Time) (*FileHashes, error) {
	header := &zip.FileHeader{
		Name:   zipPath,
		Method: zip.Deflate,
	}
	if modTime.IsZero() {
		modTime = time.Now()
	}
	header.SetModTime(modTime)

	w, err := ew.zipWriter.CreateHeader(header)
	if err != nil {
		return nil, fmt.Errorf("creating zip entry %s: %w", zipPath, err)
	}

	md5h := md5.New()
	sha256h := sha256.New()
	multi := io.MultiWriter(w, md5h, sha256h)

	var totalBytes uint64
	buf := make([]byte, 64*1024) // 64KB buffer
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := multi.Write(buf[:n]); werr != nil {
				return nil, fmt.Errorf("writing to zip: %w", werr)
			}
			totalBytes += uint64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading source: %w", err)
		}
	}

	return &FileHashes{
		MD5:       hex.EncodeToString(md5h.Sum(nil)),
		SHA256:    hex.EncodeToString(sha256h.Sum(nil)),
		SizeBytes: totalBytes,
	}, nil
}

// RecordEntry adds a manifest entry.
func (ew *EvidenceWriter) RecordEntry(entry ManifestEntry) {
	ew.manifest.Files = append(ew.manifest.Files, entry)
}

// SetOperator sets the operator field.
func (ew *EvidenceWriter) SetOperator(op string) { ew.manifest.Operator = op }

// SetCaseNumber sets the case number field.
func (ew *EvidenceWriter) SetCaseNumber(cn string) { ew.manifest.CaseNumber = cn }

// SetPlatform sets the platform field.
func (ew *EvidenceWriter) SetPlatform(p string) { ew.manifest.Platform = p }

// SetOutputFormat sets the output format field.
func (ew *EvidenceWriter) SetOutputFormat(f string) { ew.manifest.OutputFormat = f }

// GetManifest returns the current manifest (for VHD output).
func (ew *EvidenceWriter) GetManifest() *Manifest { return ew.manifest }

// Finish writes the manifest and finalizes the ZIP.
func (ew *EvidenceWriter) Finish(stats ManifestStats) (*Manifest, error) {
	now := time.Now().UTC()
	ew.manifest.CollectionEnd = &now
	ew.manifest.Stats = stats

	data, err := json.MarshalIndent(ew.manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling manifest: %w", err)
	}

	header := &zip.FileHeader{
		Name:   "manifest.json",
		Method: zip.Deflate,
	}
	header.SetModTime(now)

	w, err := ew.zipWriter.CreateHeader(header)
	if err != nil {
		return nil, fmt.Errorf("creating manifest entry: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("writing manifest: %w", err)
	}

	if err := ew.zipWriter.Close(); err != nil {
		return nil, fmt.Errorf("closing zip: %w", err)
	}

	return ew.manifest, nil
}

func generateID() string {
	b := make([]byte, 16)
	// Use timestamp-based approach (good enough for uniqueness)
	now := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		b[i] = byte(now >> (i * 8))
	}
	// Read random bytes for remaining
	f, err := os.Open("/dev/urandom")
	if err == nil {
		f.Read(b[8:])
		f.Close()
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
