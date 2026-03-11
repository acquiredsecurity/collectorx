//go:build windows

// Package vss provides Volume Shadow Copy support for collecting locked files on Windows.
package vss

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

// Snapshot represents an active VSS shadow copy.
type Snapshot struct {
	ID         string // Shadow copy ID (GUID)
	DevicePath string // e.g., \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3
}

// activeSnapshot tracks the current snapshot for cleanup on abnormal exit.
var activeSnapshot *Snapshot

func init() {
	// Register signal handler to clean up VSS snapshot on Ctrl+C / kill
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		if activeSnapshot != nil {
			fmt.Fprintf(os.Stderr, "\nCleaning up VSS snapshot %s before exit...\n", activeSnapshot.ID)
			activeSnapshot.Delete()
		}
		os.Exit(1)
	}()
}

// Available returns true on Windows.
func Available() bool { return true }

// IsVSSEnabled checks if the Volume Shadow Copy Service is running or can be started.
func IsVSSEnabled() bool {
	cmd := exec.Command("sc", "query", "VSS")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "RUNNING") ||
		strings.Contains(string(out), "STOPPED") // stopped but available
}

// CreateSnapshot creates a VSS shadow copy for the given volume (e.g., "C:\").
// Tries multiple methods in order:
//  1. vssadmin create shadow (Windows Server only)
//  2. PowerShell WMI (Win32_ShadowCopy — works on all editions including ARM64)
//
// Returns the snapshot which must be cleaned up with Delete().
func CreateSnapshot(volume string) (*Snapshot, error) {
	// Normalize volume to "C:\" format
	if len(volume) == 1 {
		volume = volume + `:\`
	} else if len(volume) == 2 && volume[1] == ':' {
		volume = volume + `\`
	}

	// Check if VSS service is available
	if !IsVSSEnabled() {
		return nil, fmt.Errorf("Volume Shadow Copy Service (VSS) is not available. " +
			"Check that the VSS service exists: sc query VSS. " +
			"If disabled, enable with: sc config VSS start= demand && net start VSS")
	}

	// Try starting VSS if it's stopped
	exec.Command("net", "start", "VSS").Run()

	// Method 1: vssadmin (Windows Server editions)
	snap, err := createViaVssadmin(volume)
	if err == nil {
		return snap, nil
	}
	fmt.Fprintf(os.Stderr, "vssadmin create not available, trying PowerShell WMI...\n")

	// Method 2: PowerShell WMI (all editions including client + ARM64)
	snap, err = createViaPowerShell(volume)
	if err == nil {
		return snap, nil
	}

	return nil, fmt.Errorf("all VSS snapshot methods failed.\nvssadmin: %v\nPowerShell: %v", err, err)
}

// createViaVssadmin uses "vssadmin create shadow" (only works on Windows Server).
func createViaVssadmin(volume string) (*Snapshot, error) {
	cmd := exec.Command("vssadmin", "create", "shadow", fmt.Sprintf("/for=%s", volume))
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	if err != nil {
		return nil, fmt.Errorf("vssadmin failed: %w — %s", err, outStr)
	}

	// Check if the command is not supported (Windows client lists "Invalid command")
	if strings.Contains(outStr, "Invalid command") {
		return nil, fmt.Errorf("vssadmin create shadow not supported on this edition")
	}

	// Parse output:
	//   Shadow Copy ID: {GUID}
	//   Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
	var shadowID, devicePath string
	for _, line := range strings.Split(outStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Shadow Copy ID:") {
			shadowID = strings.TrimSpace(strings.TrimPrefix(line, "Shadow Copy ID:"))
		}
		if strings.HasPrefix(line, "Shadow Copy Volume Name:") {
			devicePath = strings.TrimSpace(strings.TrimPrefix(line, "Shadow Copy Volume Name:"))
		}
	}

	if shadowID == "" || devicePath == "" {
		return nil, fmt.Errorf("failed to parse vssadmin output: %s", outStr)
	}

	snap := &Snapshot{ID: shadowID, DevicePath: devicePath}
	activeSnapshot = snap
	return snap, nil
}

// createViaPowerShell uses PowerShell's WMI Win32_ShadowCopy class.
// Works on all Windows editions: Client, Server, x86, ARM64.
func createViaPowerShell(volume string) (*Snapshot, error) {
	// Create the shadow copy and retrieve its ID + device path in one script
	script := fmt.Sprintf(
		`$ErrorActionPreference='Stop'; `+
			`$r=(Get-WmiObject -List Win32_ShadowCopy).Create('%s','ClientAccessible'); `+
			`$id=$r.ShadowID; `+
			`$s=Get-WmiObject Win32_ShadowCopy | Where-Object {$_.ID -eq $id}; `+
			`Write-Output "ShadowID=$id"; `+
			`Write-Output "DeviceObject=$($s.DeviceObject)"`,
		volume)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	if err != nil {
		return nil, fmt.Errorf("PowerShell WMI create failed: %w\nOutput: %s", err, outStr)
	}

	var shadowID, devicePath string
	for _, line := range strings.Split(outStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ShadowID=") {
			shadowID = strings.TrimPrefix(line, "ShadowID=")
		}
		if strings.HasPrefix(line, "DeviceObject=") {
			devicePath = strings.TrimPrefix(line, "DeviceObject=")
		}
	}

	if shadowID == "" || devicePath == "" {
		return nil, fmt.Errorf("failed to parse PowerShell output — ShadowID=%q DeviceObject=%q\nFull output: %s",
			shadowID, devicePath, outStr)
	}

	snap := &Snapshot{ID: shadowID, DevicePath: devicePath}
	activeSnapshot = snap
	return snap, nil
}

// Delete removes the VSS snapshot and clears the active snapshot tracker.
// Tries vssadmin first, falls back to PowerShell WMI.
func (s *Snapshot) Delete() error {
	if s == nil {
		return nil
	}

	// Try vssadmin delete (works on all editions)
	cmd := exec.Command("vssadmin", "delete", "shadows",
		fmt.Sprintf("/Shadow=%s", s.ID), "/quiet")
	_, err := cmd.CombinedOutput()
	if err == nil {
		activeSnapshot = nil
		return nil
	}

	// Fall back to PowerShell WMI
	script := fmt.Sprintf(
		`Get-WmiObject Win32_ShadowCopy | Where-Object {$_.ID -eq '%s'} | `+
			`ForEach-Object { $_.Delete() }`,
		s.ID)
	cmd2 := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out2, err2 := cmd2.CombinedOutput()
	if err2 != nil {
		return fmt.Errorf("failed to delete snapshot %s via vssadmin and PowerShell: %s",
			s.ID, string(out2))
	}

	activeSnapshot = nil
	return nil
}

// FilePath returns the full path to a file within the shadow copy.
// sourcePath should be like "C:\Windows\System32\config\SAM"
// Returns like "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\Windows\System32\config\SAM"
func (s *Snapshot) FilePath(sourcePath string) string {
	relative := sourcePath
	if len(sourcePath) >= 2 && sourcePath[1] == ':' {
		relative = sourcePath[2:]
	}
	relative = strings.TrimLeft(relative, `\/`)

	return s.DevicePath + `\` + relative
}
