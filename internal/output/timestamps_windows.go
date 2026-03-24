//go:build windows

package output

import (
	"os"
	"syscall"
)

// preserveTimestamps copies all three NTFS timestamps (created, modified, accessed)
// from srcInfo to the file at dstPath.
func preserveTimestamps(dstPath string, srcInfo os.FileInfo) error {
	sys := srcInfo.Sys()
	if sys == nil {
		modTime := srcInfo.ModTime()
		return os.Chtimes(dstPath, modTime, modTime)
	}

	winData, ok := sys.(*syscall.Win32FileAttributeData)
	if !ok {
		modTime := srcInfo.ModTime()
		return os.Chtimes(dstPath, modTime, modTime)
	}

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
		modTime := srcInfo.ModTime()
		return os.Chtimes(dstPath, modTime, modTime)
	}
	defer syscall.CloseHandle(h)

	ctime := winData.CreationTime
	atime := winData.LastAccessTime
	mtime := winData.LastWriteTime

	return syscall.SetFileTime(h, &ctime, &atime, &mtime)
}
