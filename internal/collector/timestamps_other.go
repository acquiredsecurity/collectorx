//go:build !windows

package collector

import (
	"os"
	"time"
)

// preserveTimestamps sets modification and access time on non-Windows platforms.
// Creation time cannot be set on most Unix filesystems.
func preserveTimestamps(dstPath string, srcInfo os.FileInfo) error {
	modTime := srcInfo.ModTime()
	return os.Chtimes(dstPath, modTime, modTime)
}

// sourceTimestamps extracts timestamps from file info.
// On non-Windows platforms, only modification time is reliably available.
func sourceTimestamps(info os.FileInfo) (created, accessed, modified time.Time) {
	modified = info.ModTime()
	accessed = modified
	created = modified
	return created, accessed, modified
}
