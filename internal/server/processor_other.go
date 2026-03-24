//go:build !windows && !linux && !darwin

package server

// platformTools returns an empty list on unsupported platforms (e.g., FreeBSD, etc.).
// CollectorX can still collect artifacts but has no platform-specific
// AS-Tools processors available for post-collection parsing.
func platformTools() []toolDef {
	return nil
}
