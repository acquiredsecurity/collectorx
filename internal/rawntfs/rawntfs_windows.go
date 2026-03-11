//go:build windows

// Package rawntfs provides raw NTFS volume access for reading locked files
// and NTFS metafiles ($MFT, $UsnJrnl, $Secure, etc.) on live Windows systems.
// Uses the go-ntfs library to parse NTFS structures directly from a raw volume handle.
package rawntfs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"www.velocidex.com/golang/go-ntfs/parser"
)

// Available returns true on Windows.
func Available() bool { return true }

// Reader provides raw NTFS access to a volume.
type Reader struct {
	volumeHandle *os.File
	ntfsCtx      *parser.NTFSContext
}

// Open opens a raw NTFS volume for reading.
// volumeLetter should be like "C" or "C:".
func Open(volumeLetter string) (*Reader, error) {
	letter := strings.ToUpper(volumeLetter[:1])
	devicePath := `\\.\` + letter + ":"

	f, err := os.Open(devicePath)
	if err != nil {
		return nil, fmt.Errorf("opening raw volume %s: %w", devicePath, err)
	}

	// PagedReader handles sector-aligned I/O with LRU caching.
	// Page size 0x1000 (4KB), cache 10000 pages (~40MB cache).
	paged, err := parser.NewPagedReader(f, 0x1000, 10000)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("creating paged reader: %w", err)
	}

	ctx, err := parser.GetNTFSContext(paged, 0)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("parsing NTFS boot sector: %w", err)
	}

	return &Reader{volumeHandle: f, ntfsCtx: ctx}, nil
}

// Close releases the raw volume handle.
func (r *Reader) Close() error {
	if r != nil && r.volumeHandle != nil {
		return r.volumeHandle.Close()
	}
	return nil
}

// CopyFile reads a file from the raw NTFS volume and writes it to destPath.
// sourcePath is the Windows path (e.g., "C:\$MFT", "C:\Windows\System32\config\SAM",
// "C:\$Extend\$UsnJrnl:$J", "C:\$Secure:$SDS").
func (r *Reader) CopyFile(sourcePath, destPath string) (uint64, error) {
	ntfsPath := toNTFSPath(sourcePath)

	data, err := parser.GetDataForPath(r.ntfsCtx, ntfsPath)
	if err != nil {
		return 0, fmt.Errorf("raw NTFS open %q: %w", ntfsPath, err)
	}

	// Create destination directory
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return 0, fmt.Errorf("creating dir: %w", err)
	}

	dst, err := os.Create(destPath)
	if err != nil {
		return 0, fmt.Errorf("creating dest: %w", err)
	}
	defer dst.Close()

	// Copy using ranges — handles sparse files efficiently
	ranges := data.Ranges()
	if len(ranges) == 0 {
		return 0, nil // Empty file
	}

	buf := make([]byte, 64*1024) // 64KB read buffer
	var totalBytes uint64

	for _, rng := range ranges {
		if rng.IsSparse {
			continue
		}

		// Seek to correct position in output file
		if _, err := dst.Seek(rng.Offset, io.SeekStart); err != nil {
			return totalBytes, fmt.Errorf("seeking to offset %d: %w", rng.Offset, err)
		}

		offset := rng.Offset
		remaining := rng.Length

		for remaining > 0 {
			toRead := int64(len(buf))
			if toRead > remaining {
				toRead = remaining
			}
			n, err := data.ReadAt(buf[:toRead], offset)
			if n > 0 {
				written, werr := dst.Write(buf[:n])
				if werr != nil {
					return totalBytes, werr
				}
				totalBytes += uint64(written)
				offset += int64(n)
				remaining -= int64(n)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return totalBytes, fmt.Errorf("reading at offset %d: %w", offset, err)
			}
		}
	}

	return totalBytes, nil
}

// toNTFSPath converts a Windows path to an NTFS-relative path.
// "C:\$MFT" -> "$MFT"
// "C:\$Extend\$UsnJrnl:$J" -> "$Extend/$UsnJrnl:$J"
// "C:\Windows\System32\config\SAM" -> "Windows/System32/config/SAM"
func toNTFSPath(windowsPath string) string {
	path := windowsPath
	// Strip drive letter
	if len(path) >= 2 && path[1] == ':' {
		path = path[2:]
	}
	path = strings.TrimLeft(path, "\\/")
	path = strings.ReplaceAll(path, "\\", "/")
	return path
}
