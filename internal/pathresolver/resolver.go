// Package pathresolver expands KAPE-style path variables into concrete filesystem paths.
package pathresolver

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Platform identifies the target OS for path resolution.
type Platform string

const (
	PlatformWindows Platform = "windows"
	PlatformMacOS   Platform = "mac"
	PlatformLinux   Platform = "linux"
)

// DetectPlatform returns the current runtime platform.
func DetectPlatform() Platform {
	switch runtime.GOOS {
	case "darwin":
		return PlatformMacOS
	case "linux":
		return PlatformLinux
	default:
		return PlatformWindows
	}
}

// ParsePlatform parses a platform string, returning the detected platform if empty.
func ParsePlatform(s string) Platform {
	switch strings.ToLower(s) {
	case "windows", "win":
		return PlatformWindows
	case "mac", "macos", "darwin":
		return PlatformMacOS
	case "linux":
		return PlatformLinux
	default:
		return DetectPlatform()
	}
}

// TargetsSubdir returns the targets subdirectory name for the platform.
func (p Platform) TargetsSubdir() string {
	switch p {
	case PlatformMacOS:
		return "macOS"
	case PlatformLinux:
		return "Linux"
	default:
		return "" // Windows loads from all non-macOS/Linux dirs (legacy compat)
	}
}

// DefaultTriageTarget returns the default triage target name for the platform.
func (p Platform) DefaultTriageTarget() string {
	switch p {
	case PlatformMacOS:
		return "MacForensicTriage.tkape"
	case PlatformLinux:
		return "LinuxForensicTriage.tkape"
	default:
		return "ForensicTriage.tkape"
	}
}

// Resolver expands KAPE-style variables in paths.
type Resolver struct {
	variables    map[string]string // lowercase key -> value
	userProfiles []string          // discovered user profile paths
	platform     Platform
	sourceRoot   string
}

// New creates a resolver with explicit mappings.
func New(variables map[string]string, userProfiles []string) *Resolver {
	return &Resolver{
		variables:    variables,
		userProfiles: userProfiles,
		platform:     PlatformWindows,
	}
}

// NewFromSourceRoot builds a resolver for a given source root directory and platform.
func NewFromSourceRoot(sourceRoot string, platform Platform) *Resolver {
	r := &Resolver{
		variables:  make(map[string]string),
		platform:   platform,
		sourceRoot: sourceRoot,
	}

	switch platform {
	case PlatformMacOS:
		r.variables["%systemlibrary%"] = filepath.Join(sourceRoot, "Library")
		r.variables["%userlibrary%"] = "Library" // relative, expanded with %user%
		r.userProfiles = discoverMacUserProfiles(sourceRoot)
	case PlatformLinux:
		r.variables["%etcdir%"] = filepath.Join(sourceRoot, "etc")
		r.variables["%varlog%"] = filepath.Join(sourceRoot, "var", "log")
		r.userProfiles = discoverLinuxUserProfiles(sourceRoot)
	default: // Windows
		r.variables["%systemroot%"] = filepath.Join(sourceRoot, "Windows")
		r.variables["%windir%"] = filepath.Join(sourceRoot, "Windows")
		r.variables["%programdata%"] = filepath.Join(sourceRoot, "ProgramData")
		r.variables["%programfiles%"] = filepath.Join(sourceRoot, "Program Files")
		r.variables["%programfiles(x86)%"] = filepath.Join(sourceRoot, "Program Files (x86)")
		r.userProfiles = discoverWindowsUserProfiles(sourceRoot)
	}

	return r
}

// Platform returns the resolver's platform.
func (r *Resolver) Platform() Platform {
	return r.platform
}

// UserProfiles returns the discovered user profile paths.
func (r *Resolver) UserProfiles() []string {
	return r.userProfiles
}

// Expand expands a KAPE-style path into one or more concrete paths.
// If the path contains %user%, it is expanded once per user profile.
// For macOS/Linux, paths starting with / are treated as absolute from source root.
func (r *Resolver) Expand(path string) []string {
	expanded := r.expandVariables(path)

	if containsCI(expanded, "%user%") {
		var results []string
		for _, profile := range r.userProfiles {
			result := replaceCI(expanded, "%user%", profile)
			results = append(results, result)
		}
		return results
	}

	return []string{expanded}
}

func (r *Resolver) expandVariables(path string) string {
	result := path
	for varName, value := range r.variables {
		result = replaceCI(result, varName, value)
	}
	return result
}

func containsCI(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func replaceCI(haystack, needle, replacement string) string {
	lowerH := strings.ToLower(haystack)
	lowerN := strings.ToLower(needle)

	var b strings.Builder
	b.Grow(len(haystack))
	start := 0
	for {
		idx := strings.Index(lowerH[start:], lowerN)
		if idx < 0 {
			break
		}
		abs := start + idx
		b.WriteString(haystack[start:abs])
		b.WriteString(replacement)
		start = abs + len(needle)
	}
	b.WriteString(haystack[start:])
	return b.String()
}

// discoverWindowsUserProfiles finds user profile directories on Windows source.
// On modern Windows (Vista+), only scans "Users". "Documents and Settings"
// is a junction to "Users" on these systems and causes duplicate/failing paths.
func discoverWindowsUserProfiles(sourceRoot string) []string {
	skip := map[string]bool{
		"default": true, "default user": true, "public": true,
		"all users": true, ".net v4.5 classic": true, ".net v4.5": true,
	}

	// If Users/ exists, we're on Vista+ — skip Documents and Settings (junction)
	usersDir := filepath.Join(sourceRoot, "Users")
	subdirs := []string{"Users", "Documents and Settings"}
	if info, err := os.Stat(usersDir); err == nil && info.IsDir() {
		subdirs = []string{"Users"}
	}

	var profiles []string
	for _, subdir := range subdirs {
		dir := filepath.Join(sourceRoot, subdir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if skip[strings.ToLower(e.Name())] {
				continue
			}
			profiles = append(profiles, e.Name())
		}
	}
	return profiles
}

// discoverMacUserProfiles finds user home directories on macOS source.
func discoverMacUserProfiles(sourceRoot string) []string {
	skip := map[string]bool{
		"shared": true, ".localized": true, "guest": true,
	}

	var profiles []string
	dir := filepath.Join(sourceRoot, "Users")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return profiles
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if skip[strings.ToLower(e.Name())] {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		profiles = append(profiles, e.Name())
	}
	return profiles
}

// discoverLinuxUserProfiles finds user home directories on Linux source.
func discoverLinuxUserProfiles(sourceRoot string) []string {
	var profiles []string

	// /home/*
	dir := filepath.Join(sourceRoot, "home")
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if strings.HasPrefix(e.Name(), ".") {
				continue
			}
			profiles = append(profiles, e.Name())
		}
	}

	// Check if /root exists
	rootDir := filepath.Join(sourceRoot, "root")
	if info, err := os.Stat(rootDir); err == nil && info.IsDir() {
		profiles = append(profiles, "root")
	}

	return profiles
}
