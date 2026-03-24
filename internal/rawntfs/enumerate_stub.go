//go:build !windows

package rawntfs

// FileEntry represents a file found via raw NTFS directory enumeration.
type FileEntry struct {
	Name     string
	FullPath string
	IsDir    bool
	Size     int64
}

// ListDirectory is not available on non-Windows platforms.
func (r *Reader) ListDirectory(dirPath string, mask string) ([]FileEntry, error) {
	return nil, nil
}

// ListDirectoryRecursive is not available on non-Windows platforms.
func (r *Reader) ListDirectoryRecursive(dirPath string, mask string) ([]FileEntry, error) {
	return nil, nil
}
