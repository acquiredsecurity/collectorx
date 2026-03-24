package output

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// VHDWriter creates a VHD (Virtual Hard Disk) Fixed image from collected evidence.
type VHDWriter struct {
	outputPath string
	vhdSize    string // e.g., "10G", "50G", "auto"
	vhdFS      string // "ntfs" or "exfat"
}

// NewVHDWriter creates a new VHD writer.
// fsType should be "ntfs" or "exfat". Defaults to "ntfs" on Windows, "exfat" elsewhere.
func NewVHDWriter(outputPath, size, fsType string) *VHDWriter {
	fs := strings.ToLower(strings.TrimSpace(fsType))
	if fs == "" || fs == "auto" {
		if runtime.GOOS == "windows" {
			fs = "ntfs"
		} else {
			fs = "exfat"
		}
	}
	return &VHDWriter{
		outputPath: outputPath,
		vhdSize:    size,
		vhdFS:      fs,
	}
}

// CreateFromDirectory creates a VHD containing all files from sourceDir.
// Returns the path to the created .vhd file.
func (w *VHDWriter) CreateFromDirectory(sourceDir, vhdName string, logWriter io.Writer) (string, error) {
	vhdPath := filepath.Join(w.outputPath, vhdName+".vhd")

	// Calculate size
	size := w.vhdSize
	if size == "" || size == "auto" {
		dirSize, err := calculateDirSize(sourceDir)
		if err != nil {
			return "", fmt.Errorf("calculating directory size: %w", err)
		}
		// Add 50% headroom + 128MB for filesystem overhead
		sizeBytes := uint64(float64(dirSize)*1.5) + 128*1024*1024
		// Round up to nearest MB
		sizeMB := (sizeBytes + 1024*1024 - 1) / (1024 * 1024)
		if sizeMB < 64 {
			sizeMB = 64 // minimum 64MB
		}
		size = fmt.Sprintf("%dM", sizeMB)
	}

	fmt.Fprintf(logWriter, "Creating VHD (%s, %s)...\n", size, strings.ToUpper(w.vhdFS))

	switch runtime.GOOS {
	case "darwin":
		return w.createOnMacOS(sourceDir, vhdPath, size, logWriter)
	case "linux":
		return w.createOnLinux(sourceDir, vhdPath, size, logWriter)
	case "windows":
		return w.createOnWindows(sourceDir, vhdPath, size, logWriter)
	default:
		return "", fmt.Errorf("VHD creation not supported on %s", runtime.GOOS)
	}
}

// createOnMacOS uses hdiutil to create a sparse ExFAT image, populates it, then converts to raw + VHD footer.
func (w *VHDWriter) createOnMacOS(sourceDir, vhdPath, size string, logWriter io.Writer) (string, error) {
	sizeBytes := parseSizeString(size)
	if sizeBytes == 0 {
		return "", fmt.Errorf("invalid VHD size: %s", size)
	}

	sparseImage := vhdPath + ".sparseimage"
	rawPath := vhdPath + ".raw.tmp"
	defer os.Remove(sparseImage)
	defer os.Remove(rawPath)

	// Step 1: Create ExFAT sparse image (hdiutil creates, formats, and mounts in one step)
	// Note: macOS always uses ExFAT (no native NTFS write support)
	fmt.Fprintf(logWriter, "  Creating ExFAT disk image...\n")
	createOut, err := exec.Command("hdiutil", "create",
		"-size", size,
		"-fs", "ExFAT",
		"-volname", "Evidence",
		"-type", "SPARSE",
		"-attach",
		sparseImage,
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("hdiutil create: %w — %s", err, string(createOut))
	}

	// Find the mount point
	mountPoint := "/Volumes/Evidence"
	for i := 0; i < 10; i++ {
		if info, serr := os.Stat(mountPoint); serr == nil && info.IsDir() {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if _, err := os.Stat(mountPoint); err != nil {
		return "", fmt.Errorf("ExFAT volume not mounted at %s", mountPoint)
	}

	// Step 2: Copy evidence files
	fmt.Fprintf(logWriter, "  Copying evidence files...\n")
	fileCount, err := copyTree(sourceDir, mountPoint)
	if err != nil {
		// Attempt cleanup
		exec.Command("hdiutil", "detach", mountPoint, "-force").Run()
		return "", fmt.Errorf("copying files: %w", err)
	}
	fmt.Fprintf(logWriter, "  Copied %d files into VHD\n", fileCount)

	// Step 3: Detach
	fmt.Fprintf(logWriter, "  Unmounting...\n")
	if out, err := exec.Command("hdiutil", "detach", mountPoint).CombinedOutput(); err != nil {
		exec.Command("hdiutil", "detach", mountPoint, "-force").Run()
		_ = out
	}

	// Step 4: Convert sparse image to flat raw
	fmt.Fprintf(logWriter, "  Converting to raw...\n")
	convertOut, err := exec.Command("hdiutil", "convert",
		sparseImage,
		"-format", "UDTO", // DVD/CD-R master (flat raw)
		"-o", rawPath,
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("hdiutil convert: %w — %s", err, string(convertOut))
	}

	// hdiutil -format UDTO appends .cdr extension
	cdrPath := rawPath + ".cdr"
	if _, err := os.Stat(cdrPath); err == nil {
		rawPath = cdrPath
		defer os.Remove(cdrPath)
	}

	// Get actual raw size for VHD footer
	rawInfo, err := os.Stat(rawPath)
	if err != nil {
		return "", fmt.Errorf("stat raw image: %w", err)
	}
	actualSize := uint64(rawInfo.Size())

	// Step 5: Write VHD = raw + footer
	fmt.Fprintf(logWriter, "  Writing VHD with footer...\n")
	if err := rawToVHDFixed(rawPath, vhdPath, actualSize); err != nil {
		return "", fmt.Errorf("writing VHD: %w", err)
	}

	fmt.Fprintf(logWriter, "VHD created: %s\n", vhdPath)
	return vhdPath, nil
}

// createOnLinux uses mkfs.exfat and loop devices to create the VHD.
func (w *VHDWriter) createOnLinux(sourceDir, vhdPath, size string, logWriter io.Writer) (string, error) {
	sizeBytes := parseSizeString(size)
	if sizeBytes == 0 {
		return "", fmt.Errorf("invalid VHD size: %s", size)
	}

	rawPath := vhdPath + ".raw.tmp"
	defer os.Remove(rawPath)

	// Create sparse file
	f, err := os.Create(rawPath)
	if err != nil {
		return "", fmt.Errorf("creating raw image: %w", err)
	}
	if err := f.Truncate(int64(sizeBytes)); err != nil {
		f.Close()
		return "", fmt.Errorf("truncating: %w", err)
	}
	f.Close()

	// Format as ExFAT (no partition table — superfloppy)
	fmt.Fprintf(logWriter, "  Formatting ExFAT...\n")
	mkfsPath, err := exec.LookPath("mkfs.exfat")
	if err != nil {
		// Fall back to mkexfatfs
		mkfsPath, err = exec.LookPath("mkexfatfs")
		if err != nil {
			return "", fmt.Errorf("neither mkfs.exfat nor mkexfatfs found — install exfatprogs")
		}
	}
	if out, err := exec.Command(mkfsPath, "-n", "Evidence", rawPath).CombinedOutput(); err != nil {
		return "", fmt.Errorf("mkfs.exfat: %w — %s", err, string(out))
	}

	// Set up loop device and mount
	fmt.Fprintf(logWriter, "  Mounting via loop device...\n")
	losetupOut, err := exec.Command("losetup", "--find", "--show", rawPath).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("losetup: %w — %s", err, string(losetupOut))
	}
	loopDev := strings.TrimSpace(string(losetupOut))
	defer exec.Command("losetup", "-d", loopDev).Run()

	mountPoint, err := os.MkdirTemp("", "vhd-mount-*")
	if err != nil {
		return "", fmt.Errorf("creating mount point: %w", err)
	}
	defer os.Remove(mountPoint)

	if out, err := exec.Command("mount", "-t", "exfat", loopDev, mountPoint).CombinedOutput(); err != nil {
		return "", fmt.Errorf("mount: %w — %s", err, string(out))
	}
	defer exec.Command("umount", mountPoint).Run()

	// Copy files
	fmt.Fprintf(logWriter, "  Copying evidence files...\n")
	fileCount, err := copyTree(sourceDir, mountPoint)
	if err != nil {
		return "", fmt.Errorf("copying files: %w", err)
	}
	fmt.Fprintf(logWriter, "  Copied %d files into VHD\n", fileCount)

	// Unmount and detach
	exec.Command("umount", mountPoint).Run()
	exec.Command("losetup", "-d", loopDev).Run()

	// Convert to VHD
	fmt.Fprintf(logWriter, "  Writing VHD with footer...\n")
	if err := rawToVHDFixed(rawPath, vhdPath, sizeBytes); err != nil {
		return "", fmt.Errorf("writing VHD: %w", err)
	}

	fmt.Fprintf(logWriter, "VHD created: %s\n", vhdPath)
	return vhdPath, nil
}

// createOnWindows uses diskpart to create and populate a VHD natively.
func (w *VHDWriter) createOnWindows(sourceDir, vhdPath, size string, logWriter io.Writer) (string, error) {
	sizeBytes := parseSizeString(size)
	if sizeBytes == 0 {
		return "", fmt.Errorf("invalid VHD size: %s", size)
	}
	sizeMB := sizeBytes / (1024 * 1024)

	// Create diskpart script
	scriptPath := vhdPath + ".diskpart.tmp"
	defer os.Remove(scriptPath)

	script := fmt.Sprintf(`create vdisk file="%s" maximum=%d type=fixed
select vdisk file="%s"
attach vdisk
create partition primary
format fs=%s label="Evidence" quick
assign letter=V
`, vhdPath, sizeMB, vhdPath, w.vhdFS)

	if err := os.WriteFile(scriptPath, []byte(script), 0o644); err != nil {
		return "", fmt.Errorf("writing diskpart script: %w", err)
	}

	fmt.Fprintf(logWriter, "  Creating VHD via diskpart...\n")
	if out, err := exec.Command("diskpart", "/s", scriptPath).CombinedOutput(); err != nil {
		return "", fmt.Errorf("diskpart create: %w — %s", err, string(out))
	}

	// Wait for volume to appear
	mountPoint := `V:\`
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(mountPoint); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Copy files
	fmt.Fprintf(logWriter, "  Copying evidence files...\n")
	fileCount, err := copyTree(sourceDir, mountPoint)
	if err != nil {
		// Attempt cleanup
		detachVHDWindows(vhdPath)
		return "", fmt.Errorf("copying files: %w", err)
	}
	fmt.Fprintf(logWriter, "  Copied %d files into VHD\n", fileCount)

	// Detach VHD
	detachVHDWindows(vhdPath)

	fmt.Fprintf(logWriter, "VHD created: %s\n", vhdPath)
	return vhdPath, nil
}

func detachVHDWindows(vhdPath string) {
	script := fmt.Sprintf(`select vdisk file="%s"
detach vdisk
`, vhdPath)
	tmpScript, err := os.CreateTemp("", "detach-*.diskpart")
	if err != nil {
		return
	}
	tmpScript.WriteString(script)
	tmpScript.Close()
	defer os.Remove(tmpScript.Name())
	exec.Command("diskpart", "/s", tmpScript.Name()).Run()
}

// rawToVHDFixed reads a raw image file and writes a VHD Fixed format file
// (raw data + 512-byte Microsoft VHD footer).
func rawToVHDFixed(rawPath, vhdPath string, sizeBytes uint64) error {
	src, err := os.Open(rawPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(vhdPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	// Copy raw data
	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copying raw data: %w", err)
	}

	// Write VHD footer
	footer := makeVHDFooter(sizeBytes)
	if _, err := dst.Write(footer); err != nil {
		return fmt.Errorf("writing VHD footer: %w", err)
	}

	return nil
}

// makeVHDFooter builds a 512-byte VHD Fixed Hard Disk Footer per Microsoft spec.
// Reference: https://learn.microsoft.com/en-us/windows/win32/vstor/about-vhd
func makeVHDFooter(diskSizeBytes uint64) []byte {
	footer := make([]byte, 512)

	// Cookie: "conectix" (8 bytes)
	copy(footer[0:8], []byte("conectix"))

	// Features: 0x00000002 (Reserved, must be set)
	binary.BigEndian.PutUint32(footer[8:12], 0x00000002)

	// File Format Version: 0x00010000 (1.0)
	binary.BigEndian.PutUint32(footer[12:16], 0x00010000)

	// Data Offset: 0xFFFFFFFFFFFFFFFF (Fixed disk — no dynamic header)
	binary.BigEndian.PutUint64(footer[16:24], 0xFFFFFFFFFFFFFFFF)

	// Time Stamp: seconds since 2000-01-01 00:00:00 UTC
	epoch := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	stamp := uint32(time.Now().UTC().Sub(epoch).Seconds())
	binary.BigEndian.PutUint32(footer[24:28], stamp)

	// Creator Application: "fcol" (forensic-collect)
	copy(footer[28:32], []byte("fcol"))

	// Creator Version: 0x00060000 (v0.6)
	binary.BigEndian.PutUint32(footer[32:36], 0x00060000)

	// Creator Host OS: 0x4D616320 ("Mac ") for macOS, 0x5769326B ("Wi2k") for Windows
	switch runtime.GOOS {
	case "windows":
		copy(footer[36:40], []byte("Wi2k"))
	default:
		copy(footer[36:40], []byte("Mac "))
	}

	// Original Size (bytes)
	binary.BigEndian.PutUint64(footer[40:48], diskSizeBytes)

	// Current Size (bytes) — same as original for fixed
	binary.BigEndian.PutUint64(footer[48:56], diskSizeBytes)

	// Disk Geometry: CHS
	cylinders, heads, sectorsPerTrack := calculateCHS(diskSizeBytes)
	binary.BigEndian.PutUint16(footer[56:58], cylinders)
	footer[58] = heads
	footer[59] = sectorsPerTrack

	// Disk Type: 2 = Fixed hard disk
	binary.BigEndian.PutUint32(footer[60:64], 2)

	// Checksum: ones' complement of the sum of all bytes (excluding checksum field)
	// Checksum is at offset 64, 4 bytes
	// First zero the checksum field
	binary.BigEndian.PutUint32(footer[64:68], 0)

	// Unique ID (16 bytes at offset 68) — use timestamp + random
	uid := generateUniqueID()
	copy(footer[68:84], uid)

	// Saved State: 0
	footer[84] = 0

	// Reserved: bytes 85-511 are zero (already zeroed)

	// Compute checksum
	var sum uint32
	for _, b := range footer {
		sum += uint32(b)
	}
	binary.BigEndian.PutUint32(footer[64:68], ^sum)

	return footer
}

// calculateCHS computes the CHS geometry for a given disk size per the VHD spec.
func calculateCHS(sizeBytes uint64) (uint16, uint8, uint8) {
	totalSectors := sizeBytes / 512
	if totalSectors > 65535*16*255 {
		totalSectors = 65535 * 16 * 255
	}

	var cylinders, heads, sectorsPerTrack uint64

	if totalSectors >= 65535*16*63 {
		sectorsPerTrack = 255
		heads = 16
		cylinders = totalSectors / (heads * sectorsPerTrack)
	} else {
		sectorsPerTrack = 17
		cylinders = totalSectors / sectorsPerTrack

		heads = (cylinders + 1023) / 1024
		if heads < 4 {
			heads = 4
		}
		if cylinders >= heads*1024 || heads > 16 {
			sectorsPerTrack = 31
			heads = 16
			cylinders = totalSectors / (heads * sectorsPerTrack)
		}
		if cylinders >= heads*1024 {
			sectorsPerTrack = 63
			heads = 16
			cylinders = totalSectors / (heads * sectorsPerTrack)
		}
	}

	if cylinders > 65535 {
		cylinders = 65535
	}

	return uint16(cylinders), uint8(heads), uint8(sectorsPerTrack)
}

// generateUniqueID creates a 16-byte UUID for the VHD footer.
func generateUniqueID() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID
		now := time.Now().UnixNano()
		for i := 0; i < 16; i++ {
			b[i] = byte(now >> (i * 4))
		}
	}
	return b
}

// parseSizeString converts "10G", "500M", etc. to bytes.
func parseSizeString(s string) uint64 {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return 0
	}

	multiplier := uint64(1)
	numStr := s
	lastChar := s[len(s)-1]
	switch lastChar {
	case 'G', 'g':
		multiplier = 1024 * 1024 * 1024
		numStr = s[:len(s)-1]
	case 'M', 'm':
		multiplier = 1024 * 1024
		numStr = s[:len(s)-1]
	case 'K', 'k':
		multiplier = 1024
		numStr = s[:len(s)-1]
	case 'T', 't':
		multiplier = 1024 * 1024 * 1024 * 1024
		numStr = s[:len(s)-1]
	}

	var n uint64
	fmt.Sscanf(numStr, "%d", &n)
	return n * multiplier
}

// calculateDirSize calculates the total size of files in a directory.
func calculateDirSize(dir string) (uint64, error) {
	var total uint64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		total += uint64(info.Size())
		return nil
	})
	return total, err
}

// copyTree recursively copies all files from src to dst, preserving directory structure.
func copyTree(src, dst string) (int, error) {
	count := 0
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return nil
		}

		destPath := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(destPath, 0o755)
		}

		if err := copyFile(path, destPath); err != nil {
			return nil // skip individual file errors
		}
		count++
		return nil
	})
	return count, err
}

// copyFile copies a single file from src to dst, preserving all timestamps.
func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	// Grab source timestamps before copying
	srcInfo, statErr := in.Stat()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}

	// Preserve original timestamps (created + modified + accessed) on the copy
	if statErr == nil {
		_ = preserveTimestamps(dst, srcInfo)
	}

	return nil
}
