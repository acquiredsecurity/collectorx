//go:build !windows

package vss

import "time"

// ShadowInfo describes an existing VSS shadow copy.
type ShadowInfo struct {
	ID           string    `json:"id"`
	DevicePath   string    `json:"devicePath"`
	VolumeName   string    `json:"volumeName"`
	CreationTime time.Time `json:"creationTime"`
}

// ListShadows is not available on non-Windows platforms.
func ListShadows() ([]ShadowInfo, error) {
	return nil, nil
}

// CollectFromShadow is not available on non-Windows platforms.
func CollectFromShadow(shadow ShadowInfo) string {
	return ""
}
