//go:build !windows

package output

import "os"

// preserveTimestamps sets modification and access time on non-Windows platforms.
func preserveTimestamps(dstPath string, srcInfo os.FileInfo) error {
	modTime := srcInfo.ModTime()
	return os.Chtimes(dstPath, modTime, modTime)
}
