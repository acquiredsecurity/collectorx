//go:build !windows

// Package rawntfs provides raw NTFS volume access — stub for non-Windows platforms.
package rawntfs

import "fmt"

// Available returns false on non-Windows platforms.
func Available() bool { return false }

// Reader is a stub on non-Windows.
type Reader struct{}

// Open is not available on non-Windows platforms.
func Open(volumeLetter string) (*Reader, error) {
	return nil, fmt.Errorf("raw NTFS access is only available on Windows")
}

// Close is a no-op on non-Windows.
func (r *Reader) Close() error { return nil }

// CopyFile is not available on non-Windows.
func (r *Reader) CopyFile(sourcePath, destPath string) (uint64, error) {
	return 0, fmt.Errorf("raw NTFS access is only available on Windows")
}
