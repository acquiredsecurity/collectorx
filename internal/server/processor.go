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
	Available   bool   `json:"available"`
	binaryPath  string
	buildArgs   func(inputPath, outputPath string) []string
}

// ProcessorRegistry holds all known processors and their availability.
type ProcessorRegistry struct {
	toolsDir   string
	processors []ProcessorDef
}

// NewProcessorRegistry creates a registry and discovers available tools.
func NewProcessorRegistry(toolsDir string) *ProcessorRegistry {
	r := &ProcessorRegistry{toolsDir: toolsDir}

	// dirArgs: tool -d <input> --out <output>
	dirArgs := func(input, output string) []string {
		return []string{"-d", input, "--out", output}
	}
	// scanArgs: tool scan -d <input> --out <output>
	scanArgs := func(input, output string) []string {
		return []string{"scan", "-d", input, "--out", output}
	}

	// All 21 AS-Tools processors with correct binary names and CLI patterns
	type toolDef struct {
		id, name, desc, category string
		args                     func(string, string) []string
	}

	known := []toolDef{
		{"evtx", "evtx", "Windows Event Log parser (.evtx) with Sigma rule support", "EventLogs", dirArgs},
		{"mftx", "mftx", "NTFS Master File Table parser ($MFT) with timestomp detection", "FileSystem", dirArgs},
		{"pfx", "pfx", "Windows Prefetch execution evidence parser (.pf)", "Execution", scanArgs},
		{"regx", "regx", "Windows Registry parser (SAM, SYSTEM, SOFTWARE, NTUSER)", "Registry", dirArgs},
		{"usnx", "usnx", "NTFS USN Change Journal parser ($UsnJrnl:$J)", "FileSystem", dirArgs},
		{"lnkx", "lnkx", "LNK shortcut and Jump List parser", "FileSystem", dirArgs},
		{"srumx", "srumx", "System Resource Usage Monitor parser (SRUDB.dat)", "SystemActivity", scanArgs},
		{"amcachex", "amcachex", "Amcache.hve application execution evidence parser", "Execution", scanArgs},
		{"rbx", "rbx", "Recycle Bin $I file deletion evidence parser", "FileSystem", scanArgs},
		{"etlx", "etlx", "Windows ETL trace log parser (kernel + ETW events)", "EventLogs", dirArgs},
		{"aix", "aix", "AI chat history parser (Claude Code, ChatGPT)", "Applications",
			func(input, output string) []string { return []string{"scan", "-d", input, "-o", output} }},
		{"defx", "defx", "Windows Defender log parser (MPLog, MPDetection)", "Antivirus", dirArgs},
		{"ntdsx", "ntdsx", "Active Directory NTDS.dit hash extractor", "ActiveDirectory", scanArgs},
		{"wmix", "wmix", "WMI repository persistence artifact parser (OBJECTS.DATA)", "Persistence", dirArgs},
		{"schtskx", "schtskx", "Scheduled Tasks XML parser", "Persistence", dirArgs},
		{"shellbagx", "shellbagx", "Registry shellbag navigation history parser", "Registry", dirArgs},
		{"webx", "webx", "Browser history analyzer (Chrome, Firefox, Edge, Brave, Arc)", "Applications", scanArgs},
		{"pshx", "pshx", "PowerShell ConsoleHost_history parser", "Applications",
			func(input, output string) []string { return []string{input, "-o", output} }},
		{"vpnx", "vpnx", "SSL VPN log parser (Fortinet, Cisco, SonicWall, Ivanti)", "Network", dirArgs},
		{"wtlx", "wtlx", "Windows Timeline and Search Index parser", "UserActivity", scanArgs},
		{"carverx", "carverx", "Forensic file carving tool (E01, raw/dd images)", "FileSystem",
			func(input, output string) []string { return []string{"-i", input, "--out", output} }},
	}

	for _, k := range known {
		def := ProcessorDef{
			ID:          k.id,
			Name:        k.name,
			Description: k.desc,
			Category:    k.category,
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
