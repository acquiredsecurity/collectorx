//go:build windows

package vss

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ShadowInfo describes an existing VSS shadow copy.
type ShadowInfo struct {
	ID           string    `json:"id"`
	DevicePath   string    `json:"devicePath"`
	VolumeName   string    `json:"volumeName"`
	CreationTime time.Time `json:"creationTime"`
}

// ListShadows enumerates all existing VSS shadow copies on the system.
func ListShadows() ([]ShadowInfo, error) {
	// Try vssadmin first
	shadows, err := listViaVssadmin()
	if err == nil && len(shadows) > 0 {
		return shadows, nil
	}

	// Fall back to PowerShell WMI
	return listViaPowerShell()
}

func listViaVssadmin() ([]ShadowInfo, error) {
	cmd := exec.Command("vssadmin", "list", "shadows")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("vssadmin list shadows: %w", err)
	}

	var shadows []ShadowInfo
	var current ShadowInfo
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Shadow Copy ID:") {
			if current.ID != "" {
				shadows = append(shadows, current)
			}
			current = ShadowInfo{}
			current.ID = strings.TrimSpace(strings.TrimPrefix(line, "Shadow Copy ID:"))
		}
		if strings.HasPrefix(line, "Shadow Copy Volume:") {
			current.DevicePath = strings.TrimSpace(strings.TrimPrefix(line, "Shadow Copy Volume:"))
		}
		if strings.HasPrefix(line, "Original Volume:") {
			current.VolumeName = strings.TrimSpace(strings.TrimPrefix(line, "Original Volume:"))
		}
		if strings.HasPrefix(line, "Creation Time:") || strings.HasPrefix(line, "Originating Machine:") {
			// Try to parse the creation time
			timeStr := strings.TrimSpace(strings.TrimPrefix(line, "Creation Time:"))
			if t, err := time.Parse("1/2/2006 3:04:05 PM", timeStr); err == nil {
				current.CreationTime = t
			}
		}
	}
	if current.ID != "" {
		shadows = append(shadows, current)
	}

	return shadows, nil
}

func listViaPowerShell() ([]ShadowInfo, error) {
	script := `Get-WmiObject Win32_ShadowCopy | ForEach-Object {
		Write-Output "ID=$($_.ID)"
		Write-Output "DeviceObject=$($_.DeviceObject)"
		Write-Output "VolumeName=$($_.VolumeName)"
		Write-Output "InstallDate=$($_.InstallDate)"
		Write-Output "---"
	}`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("PowerShell list shadows: %w", err)
	}

	var shadows []ShadowInfo
	var current ShadowInfo
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "---" {
			if current.ID != "" {
				shadows = append(shadows, current)
			}
			current = ShadowInfo{}
			continue
		}
		if strings.HasPrefix(line, "ID=") {
			current.ID = strings.TrimPrefix(line, "ID=")
		}
		if strings.HasPrefix(line, "DeviceObject=") {
			current.DevicePath = strings.TrimPrefix(line, "DeviceObject=")
		}
		if strings.HasPrefix(line, "VolumeName=") {
			current.VolumeName = strings.TrimPrefix(line, "VolumeName=")
		}
		if strings.HasPrefix(line, "InstallDate=") {
			dateStr := strings.TrimPrefix(line, "InstallDate=")
			// WMI datetime format: 20260313120000.000000-300
			if len(dateStr) >= 14 {
				if t, err := time.Parse("20060102150405", dateStr[:14]); err == nil {
					current.CreationTime = t
				}
			}
		}
	}
	if current.ID != "" {
		shadows = append(shadows, current)
	}

	return shadows, nil
}

// CollectFromShadow collects files from a specific shadow copy.
// Returns the device path that can be used as a source root.
func CollectFromShadow(shadow ShadowInfo) string {
	// The device path can be used directly with trailing backslash
	path := shadow.DevicePath
	if !strings.HasSuffix(path, `\`) {
		path += `\`
	}
	return path
}
