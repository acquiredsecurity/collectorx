//go:build !windows

// Package vss provides Volume Shadow Copy support — stub for non-Windows platforms.
package vss

// Snapshot represents an active VSS shadow copy (stub).
type Snapshot struct {
	ID         string
	DevicePath string
}

// Available returns false on non-Windows platforms.
func Available() bool { return false }

// CreateSnapshot is not available on non-Windows platforms.
func CreateSnapshot(volume string) (*Snapshot, error) {
	return nil, nil
}

// Delete is a no-op on non-Windows platforms.
func (s *Snapshot) Delete() error { return nil }

// FilePath is a no-op on non-Windows platforms.
func (s *Snapshot) FilePath(sourcePath string) string { return "" }
