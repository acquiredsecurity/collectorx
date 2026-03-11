// Package pathresolver expands KAPE-style path variables into concrete filesystem paths.
package pathresolver

import (
	"os"
	"path/filepath"
	"strings"
)

// Resolver expands KAPE-style variables in paths.
type Resolver struct {
	variables    map[string]string // lowercase key -> value
	userProfiles []string          // discovered user profile paths
}

// New creates a resolver with explicit mappings.
func New(variables map[string]string, userProfiles []string) *Resolver {
	return &Resolver{
		variables:    variables,
		userProfiles: userProfiles,
	}
}

// NewFromSourceRoot builds a resolver for a given source root directory.
func NewFromSourceRoot(sourceRoot string) *Resolver {
	vars := map[string]string{
		"%systemroot%":        filepath.Join(sourceRoot, "Windows"),
		"%windir%":            filepath.Join(sourceRoot, "Windows"),
		"%programdata%":       filepath.Join(sourceRoot, "ProgramData"),
		"%programfiles%":      filepath.Join(sourceRoot, "Program Files"),
		"%programfiles(x86)%": filepath.Join(sourceRoot, "Program Files (x86)"),
	}

	profiles := discoverUserProfiles(sourceRoot)
	return New(vars, profiles)
}

// UserProfiles returns the discovered user profile paths.
func (r *Resolver) UserProfiles() []string {
	return r.userProfiles
}

// Expand expands a KAPE-style path into one or more concrete paths.
// If the path contains %user%, it is expanded once per user profile.
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

func discoverUserProfiles(sourceRoot string) []string {
	skip := map[string]bool{
		"default": true, "default user": true, "public": true,
		"all users": true, ".net v4.5 classic": true, ".net v4.5": true,
	}

	var profiles []string
	for _, subdir := range []string{"Users", "Documents and Settings"} {
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
			// Store just the username — KAPE paths like C:\Users\%user%\
			// expect %user% to be replaced with just the name
			profiles = append(profiles, e.Name())
		}
	}
	return profiles
}
