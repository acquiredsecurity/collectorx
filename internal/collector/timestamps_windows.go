//go:build windows

package collector

import (
	"os"
	"syscall"
	"time"
)

// preserveTimestamps copies all three NTFS timestamps (created, modified, accessed)
// from srcInfo to the file at dstPath. On Windows this uses SetFileTime to also
// set the creation time, which os.Chtimes cannot do.
func preserveTimestamps(dstPath string, srcInfo os.FileInfo) error {
	sys := srcInfo.Sys()
	if sys == nil {
		// Fallback: at least set mod time
		modTime := srcInfo.ModTime()
		return os.Chtimes(dstPath, modTime, modTime)
	}

	winData, ok := sys.(*syscall.Win32FileAttributeData)
	if !ok {
		modTime := srcInfo.ModTime()
		return os.Chtimes(dstPath, modTime, modTime)
	}

	// Open the destination with write-attributes permission
	pathp, err := syscall.UTF16PtrFromString(dstPath)
	if err != nil {
		return err
	}

	h, err := syscall.CreateFile(
		pathp,
		syscall.FILE_WRITE_ATTRIBUTES,
		syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		// Fallback to os.Chtimes if we can't open for attribute writes
		modTime := srcInfo.ModTime()
		return os.Chtimes(dstPath, modTime, modTime)
	}
	defer syscall.CloseHandle(h)

	// Copy all three timestamps: creation, last access, last write
	ctime := winData.CreationTime
	atime := winData.LastAccessTime
	mtime := winData.LastWriteTime

	return syscall.SetFileTime(h, &ctime, &atime, &mtime)
}

// sourceTimestamps extracts creation, access, and modification times from file info.
// On Windows, creation time comes from Win32FileAttributeData.
func sourceTimestamps(info os.FileInfo) (created, accessed, modified time.Time) {
	modified = info.ModTime()
	accessed = modified // default
	created = modified  // default

	if sys := info.Sys(); sys != nil {
		if winData, ok := sys.(*syscall.Win32FileAttributeData); ok {
			created = time.Unix(0, winData.CreationTime.Nanoseconds())
			accessed = time.Unix(0, winData.LastAccessTime.Nanoseconds())
		}
	}

	return created, accessed, modified
}
