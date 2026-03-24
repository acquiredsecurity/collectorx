package server

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// ProcessorDef defines an AS-Tools processor.
type ProcessorDef struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Platform    string `json:"platform"` // "windows" or "linux"
	Available   bool   `json:"available"`
	binaryPath  string
	buildArgs   func(inputPath, outputPath string) []string
}

// ProcessorRegistry holds all known processors and their availability.
type ProcessorRegistry struct {
	toolsDir   string
	processors []ProcessorDef
}

// toolDef is used by platform-specific files to declare tools.
type toolDef struct {
	id, name, desc, category string
	args                     func(string, string) []string
}

// Common arg patterns shared by platform-specific tool lists.
var (
	dirArgs = func(input, output string) []string {
		return []string{"-d", input, "--out", output}
	}
	scanArgs = func(input, output string) []string {
		return []string{"scan", "-d", input, "--out", output}
	}
)

// NewProcessorRegistry creates a registry and discovers available tools.
// platformTools() is provided by the build-tagged files (processor_windows.go / processor_linux.go).
func NewProcessorRegistry(toolsDir string) *ProcessorRegistry {
	r := &ProcessorRegistry{toolsDir: toolsDir}

	platformName := runtime.GOOS
	for _, k := range platformTools() {
		def := ProcessorDef{
			ID:          k.id,
			Name:        k.name,
			Description: k.desc,
			Category:    k.category,
			Platform:    platformName,
			buildArgs:   k.args,
		}
		def.binaryPath = r.findBinary(k.id)
		def.Available = def.binaryPath != ""
		r.processors = append(r.processors, def)
	}

	return r
}

// List returns all known processors with their availability status.
func (r *ProcessorRegistry) List() []ProcessorDef {
	return r.processors
}

// Get returns a processor by ID.
func (r *ProcessorRegistry) Get(id string) *ProcessorDef {
	for i := range r.processors {
		if r.processors[i].ID == id {
			return &r.processors[i]
		}
	}
	return nil
}

// Run executes a processor and streams output to the job's SSE channel.
func (r *ProcessorRegistry) Run(ctx context.Context, proc *ProcessorDef, inputPath, outputPath string, job *Job) error {
	if proc.binaryPath == "" {
		return fmt.Errorf("processor %s: binary not found", proc.ID)
	}

	args := proc.buildArgs(inputPath, outputPath)

	job.sendEvent("log", map[string]string{
		"message": fmt.Sprintf("Starting %s: %s %v", proc.Name, proc.binaryPath, args),
		"level":   "info",
	})

	cmd := exec.CommandContext(ctx, proc.binaryPath, args...)
	cmd.Dir = outputPath

	// Capture stdout
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", proc.Name, err)
	}

	// Stream stdout
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			job.sendEvent("log", map[string]string{
				"message":   scanner.Text(),
				"level":     "info",
				"processor": proc.ID,
			})
		}
	}()

	// Stream stderr
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			job.sendEvent("log", map[string]string{
				"message":   scanner.Text(),
				"level":     "warn",
				"processor": proc.ID,
			})
		}
	}()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s failed: %w", proc.Name, err)
	}

	return nil
}

// findBinary searches for a processor binary in the tools directory.
func (r *ProcessorRegistry) findBinary(id string) string {
	if r.toolsDir == "" {
		return ""
	}

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}

	// Check common locations in order of preference
	candidates := []string{
		// Direct in tools dir
		filepath.Join(r.toolsDir, id+ext),
		// Cargo release build layout
		filepath.Join(r.toolsDir, id, "target", "release", id+ext),
		// Subdirectory
		filepath.Join(r.toolsDir, id, id+ext),
	}

	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}

	return ""
}
