package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/bradleyroughan/forensic-collect/internal/collector"
	"github.com/bradleyroughan/forensic-collect/internal/export"
	"github.com/bradleyroughan/forensic-collect/internal/output"
)

// --- Request / Response types ---

type collectRequest struct {
	Source     string        `json:"source"`
	Output     string        `json:"output"`
	Targets    []string      `json:"targets"`
	CaseNumber string        `json:"caseNumber"`
	Operator   string        `json:"operator"`
	Hostname   string        `json:"hostname"`
	MaxSizeMB  uint64        `json:"maxSizeMB"`
	NoVSS      bool          `json:"noVSS"`
	Export     *export.Config `json:"export,omitempty"`
}

type processRequest struct {
	EvidencePath string   `json:"evidencePath"`
	OutputPath   string   `json:"outputPath"`
	Processors   []string `json:"processors"`
}

type targetInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	IsDefault   bool   `json:"isDefault"`
	Category    string `json:"category"`
}

// --- Handlers ---

func (s *Server) handleGetTargets(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		name string
		desc string
		cat  string
	}

	var entries []entry
	for name, t := range s.Store.All() {
		// Derive category from directory structure
		cat := "General"
		parts := strings.Split(name, "/")
		if len(parts) > 1 {
			cat = parts[0]
		}
		entries = append(entries, entry{name, t.Description, cat})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	// Mark well-known defaults based on platform
	defaultTarget := s.Platform.DefaultTriageTarget()
	defaults := map[string]bool{
		strings.ToLower(defaultTarget): true,
	}

	var result []targetInfo
	for _, e := range entries {
		result = append(result, targetInfo{
			Name:        e.name,
			Description: e.desc,
			IsDefault:   defaults[strings.ToLower(e.name)],
			Category:    e.cat,
		})
	}

	writeJSON(w, result)
}

func (s *Server) handleGetProcessors(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Processors.List())
}

// --- Browse & Drives ---

type dirEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"isDir"`
	Size  int64  `json:"size"`
}

type driveInfo struct {
	Path  string `json:"path"`
	Label string `json:"label"`
}

func (s *Server) handleBrowse(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}

	// Resolve symlinks (e.g., /tmp -> /private/tmp on macOS)
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Cannot read directory: %v", err))
		return
	}

	var result []dirEntry
	for _, e := range entries {
		// Skip hidden/system files for cleaner browsing
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		size := int64(0)
		if info, err := e.Info(); err == nil {
			size = info.Size()
		}
		result = append(result, dirEntry{
			Name:  e.Name(),
			IsDir: e.IsDir(),
			Size:  size,
		})
	}

	// Sort: directories first, then by name
	sort.Slice(result, func(i, j int) bool {
		if result[i].IsDir != result[j].IsDir {
			return result[i].IsDir
		}
		return result[i].Name < result[j].Name
	})

	writeJSON(w, map[string]any{
		"path":    path,
		"entries": result,
	})
}

func (s *Server) handleGetDrives(w http.ResponseWriter, r *http.Request) {
	var drives []driveInfo

	switch runtime.GOOS {
	case "windows":
		for _, letter := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
			path := string(letter) + ":\\"
			if _, err := os.Stat(path); err == nil {
				drives = append(drives, driveInfo{Path: path, Label: string(letter) + ":"})
			}
		}
	case "darwin":
		drives = append(drives, driveInfo{Path: "/", Label: "/"})
		if entries, err := os.ReadDir("/Volumes"); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					drives = append(drives, driveInfo{
						Path:  filepath.Join("/Volumes", e.Name()),
						Label: e.Name(),
					})
				}
			}
		}
	default: // linux
		drives = append(drives, driveInfo{Path: "/", Label: "/"})
		for _, mountDir := range []string{"/mnt", "/media"} {
			if entries, err := os.ReadDir(mountDir); err == nil {
				for _, e := range entries {
					if e.IsDir() {
						drives = append(drives, driveInfo{
							Path:  filepath.Join(mountDir, e.Name()),
							Label: e.Name(),
						})
					}
				}
			}
		}
	}

	writeJSON(w, drives)
}

// --- Export ---

type exportTestRequest struct {
	Export export.Config `json:"export"`
}

func (s *Server) handleTestExport(w http.ResponseWriter, r *http.Request) {
	var req exportTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	exporter, err := export.New(&req.Export)
	if err != nil {
		writeJSON(w, map[string]any{"success": false, "error": err.Error()})
		return
	}

	if err := exporter.TestConnection(); err != nil {
		writeJSON(w, map[string]any{"success": false, "error": err.Error()})
		return
	}

	writeJSON(w, map[string]any{"success": true, "message": "Connection successful"})
}

// --- Collection ---

func (s *Server) handleStartCollect(w http.ResponseWriter, r *http.Request) {
	var req collectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Source == "" {
		writeError(w, http.StatusBadRequest, "source path is required")
		return
	}
	if req.Output == "" {
		writeError(w, http.StatusBadRequest, "output path is required")
		return
	}

	// Normalize target names
	var targetNames []string
	for _, name := range req.Targets {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !strings.HasSuffix(name, ".tkape") {
			name += ".tkape"
		}
		targetNames = append(targetNames, name)
	}
	if len(targetNames) == 0 {
		targetNames = []string{s.Platform.DefaultTriageTarget()}
	}

	job := s.createJob("collect")
	writeJSON(w, map[string]string{"jobId": job.ID})

	// Run collection in background
	go s.runCollection(job, req, targetNames)
}

func (s *Server) runCollection(job *Job, req collectRequest, targetNames []string) {
	defer func() {
		if r := recover(); r != nil {
			job.fail(fmt.Errorf("panic: %v", r))
		}
	}()

	job.sendEvent("log", map[string]string{"message": fmt.Sprintf("Resolving targets: %v", targetNames), "level": "info"})

	// Resolve collection items using shared logic
	result, err := collector.ResolveCollectionItems(collector.ResolveConfig{
		SourceRoot:  req.Source,
		TargetNames: targetNames,
		Store:       s.Store,
		Platform:    s.Platform,
	})
	if err != nil {
		job.fail(fmt.Errorf("resolving targets: %w", err))
		return
	}

	job.sendEvent("log", map[string]string{
		"message": fmt.Sprintf("Resolved %d targets, discovered %d user profiles, %d files queued",
			result.ResolvedCount, result.UserProfiles, len(result.Items)),
		"level": "info",
	})

	if len(result.Items) == 0 {
		job.fail(fmt.Errorf("no files matched the target definitions"))
		return
	}

	// Create output and staging directories
	if err := os.MkdirAll(req.Output, 0o755); err != nil {
		job.fail(fmt.Errorf("creating output dir: %w", err))
		return
	}

	hostname := req.Hostname
	if hostname == "" {
		hostname = getHostname()
	}
	timestamp := time.Now().UTC().Format("20060102_150405")
	stagingDir := filepath.Join(req.Output, fmt.Sprintf("staging_%s_%s", hostname, timestamp))
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		job.fail(fmt.Errorf("creating staging dir: %w", err))
		return
	}
	defer os.RemoveAll(stagingDir)

	// Create and configure collection engine
	engine := collector.NewEngine(req.Source, stagingDir)
	_ = req.NoVSS // VSS is now opt-in via --vss-collect-all, not part of default collection
	if req.MaxSizeMB > 0 {
		engine.MaxFileSize = req.MaxSizeMB * 1024 * 1024
	}

	// Wire progress callback to SSE
	engine.OnProgress = func(evt collector.ProgressEvent) {
		job.sendEvent("progress", evt)
	}

	// Redirect engine logs to SSE
	engine.LogWriter = &sseLogWriter{job: job, level: "info"}
	engine.ErrWriter = &sseLogWriter{job: job, level: "warn"}

	job.sendEvent("log", map[string]string{
		"message": fmt.Sprintf("Starting collection: %d files from %s", len(result.Items), req.Source),
		"level":   "info",
	})

	collectedFiles, stats := engine.Collect(result.Items)

	// Build ZIP
	zipName := fmt.Sprintf("evidence_%s_%s.zip", hostname, timestamp)
	zipPath := filepath.Join(req.Output, zipName)

	job.sendEvent("log", map[string]string{
		"message": fmt.Sprintf("Building ZIP archive: %s", zipName),
		"level":   "info",
	})
	job.sendEvent("progress", collector.ProgressEvent{
		Phase:   "zip",
		Message: "Building ZIP archive...",
	})

	zipFile, err := os.Create(zipPath)
	if err != nil {
		job.fail(fmt.Errorf("creating ZIP: %w", err))
		return
	}

	ew := output.NewEvidenceWriter(zipFile, hostname, targetNames)
	if req.Operator != "" {
		ew.SetOperator(req.Operator)
	}
	if req.CaseNumber != "" {
		ew.SetCaseNumber(req.CaseNumber)
	}

	for i, cf := range collectedFiles {
		zipEntryPath := strings.ReplaceAll(cf.Item.DestRelPath, "\\", "/")
		hashes, err := ew.AddFile(zipEntryPath, cf.DestPath)
		if err != nil {
			job.sendEvent("log", map[string]string{
				"message": fmt.Sprintf("ERROR: adding to ZIP %s: %v", zipEntryPath, err),
				"level":   "error",
			})
			continue
		}

		ew.RecordEntry(output.ManifestEntry{
			SourcePath:   cf.Item.SourcePath,
			DestPath:     zipEntryPath,
			SizeBytes:    hashes.SizeBytes,
			MD5:          hashes.MD5,
			SHA256:       hashes.SHA256,
			CollectedVia: cf.Method,
			TargetName:   cf.Item.TargetName,
		})

		if (i+1)%50 == 0 || i == len(collectedFiles)-1 {
			job.sendEvent("progress", collector.ProgressEvent{
				Phase:   "zip",
				Current: i + 1,
				Total:   len(collectedFiles),
				Percent: float64(i+1) / float64(len(collectedFiles)) * 100,
				Message: fmt.Sprintf("Zipping files: %d/%d", i+1, len(collectedFiles)),
			})
		}
	}

	manifest, err := ew.Finish(output.ManifestStats{
		TotalFiles:   stats.FilesCollected,
		TotalBytes:   stats.BytesCollected,
		NormalFiles:  stats.NormalCount,
		RawNTFSFiles: stats.RawNTFSCount,
		VSSFiles:     stats.VSSCount,
		FailedFiles:  stats.FilesFailed,
	})
	if err != nil {
		zipFile.Close()
		job.fail(fmt.Errorf("finalizing ZIP: %w", err))
		return
	}
	zipFile.Close()

	duration := manifest.CollectionEnd.Sub(manifest.CollectionStart)

	// Export if configured
	var exportResult *export.Result
	if req.Export != nil && req.Export.Type != "" {
		job.sendEvent("log", map[string]string{
			"message": fmt.Sprintf("Starting %s export...", strings.ToUpper(req.Export.Type)),
			"level":   "info",
		})
		job.sendEvent("progress", collector.ProgressEvent{
			Phase:   "export",
			Message: fmt.Sprintf("Exporting via %s...", strings.ToUpper(req.Export.Type)),
		})

		exporter, err := export.New(req.Export)
		if err != nil {
			job.sendEvent("log", map[string]string{
				"message": fmt.Sprintf("Export setup failed: %v", err),
				"level":   "error",
			})
		} else {
			exportResult, err = exporter.Upload(zipPath, func(sent, total int64) {
				if total > 0 {
					pct := float64(sent) / float64(total) * 100
					job.sendEvent("progress", collector.ProgressEvent{
						Phase:   "export",
						Percent: pct,
						Message: fmt.Sprintf("Exporting: %s / %s", formatBytes(uint64(sent)), formatBytes(uint64(total))),
					})
				}
			})
			if err != nil {
				job.sendEvent("log", map[string]string{
					"message": fmt.Sprintf("Export failed: %v", err),
					"level":   "error",
				})
			} else {
				job.sendEvent("log", map[string]string{
					"message": fmt.Sprintf("Export complete: %s", exportResult.Message),
					"level":   "success",
				})
			}
		}
	}

	completionData := map[string]any{
		"zipPath":        zipPath,
		"hostname":       manifest.Hostname,
		"filesCollected": stats.FilesCollected,
		"filesFailed":    stats.FilesFailed,
		"bytesCollected": stats.BytesCollected,
		"normalCopy":     stats.NormalCount,
		"rawNTFS":        stats.RawNTFSCount,
		"duration":       duration.Seconds(),
	}
	if exportResult != nil {
		completionData["exportSuccess"] = exportResult.Success
		completionData["exportMessage"] = exportResult.Message
		completionData["exportBytes"] = exportResult.BytesSent
	}

	job.complete(completionData)
}

func (s *Server) handleStartProcess(w http.ResponseWriter, r *http.Request) {
	var req processRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.EvidencePath == "" {
		writeError(w, http.StatusBadRequest, "evidence path is required")
		return
	}
	if req.OutputPath == "" {
		writeError(w, http.StatusBadRequest, "output path is required")
		return
	}
	if len(req.Processors) == 0 {
		writeError(w, http.StatusBadRequest, "at least one processor must be selected")
		return
	}

	job := s.createJob("process")
	writeJSON(w, map[string]string{"jobId": job.ID})

	// Run processors in background
	go s.runProcessors(job, req)
}

func (s *Server) runProcessors(job *Job, req processRequest) {
	defer func() {
		if r := recover(); r != nil {
			job.fail(fmt.Errorf("panic: %v", r))
		}
	}()

	if err := os.MkdirAll(req.OutputPath, 0o755); err != nil {
		job.fail(fmt.Errorf("creating output dir: %w", err))
		return
	}

	total := len(req.Processors)
	succeeded := 0
	failed := 0

	for i, procID := range req.Processors {
		proc := s.Processors.Get(procID)
		if proc == nil {
			job.sendEvent("log", map[string]string{
				"message": fmt.Sprintf("Unknown processor: %s", procID),
				"level":   "error",
			})
			failed++
			continue
		}

		if !proc.Available {
			job.sendEvent("log", map[string]string{
				"message": fmt.Sprintf("Processor %s not available (binary not found)", proc.Name),
				"level":   "error",
			})
			failed++
			continue
		}

		job.sendEvent("processor_status", map[string]any{
			"id":      proc.ID,
			"name":    proc.Name,
			"status":  "running",
			"current": i + 1,
			"total":   total,
		})

		job.sendEvent("progress", map[string]any{
			"phase":   "process",
			"current": i + 1,
			"total":   total,
			"percent": float64(i+1) / float64(total) * 100,
			"message": fmt.Sprintf("Running %s (%d/%d)", proc.Name, i+1, total),
		})

		start := time.Now()
		err := s.Processors.Run(job.ctx, proc, req.EvidencePath, req.OutputPath, job)
		elapsed := time.Since(start)

		if err != nil {
			job.sendEvent("processor_status", map[string]any{
				"id":      proc.ID,
				"name":    proc.Name,
				"status":  "error",
				"error":   err.Error(),
				"elapsed": elapsed.Seconds(),
			})
			job.sendEvent("log", map[string]string{
				"message": fmt.Sprintf("%s failed after %.1fs: %v", proc.Name, elapsed.Seconds(), err),
				"level":   "error",
			})
			failed++
		} else {
			job.sendEvent("processor_status", map[string]any{
				"id":      proc.ID,
				"name":    proc.Name,
				"status":  "done",
				"elapsed": elapsed.Seconds(),
			})
			job.sendEvent("log", map[string]string{
				"message": fmt.Sprintf("%s completed in %.1fs", proc.Name, elapsed.Seconds()),
				"level":   "info",
			})
			succeeded++
		}
	}

	job.complete(map[string]any{
		"total":     total,
		"succeeded": succeeded,
		"failed":    failed,
	})
}

// sseLogWriter adapts io.Writer to send log events via SSE.
type sseLogWriter struct {
	job   *Job
	level string
}

func (w *sseLogWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimRight(string(p), "\n\r")
	if msg != "" {
		w.job.sendEvent("log", map[string]string{
			"message": msg,
			"level":   w.level,
		})
	}
	return len(p), nil
}

func getHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "UNKNOWN"
	}
	return h
}

func formatBytes(b uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d bytes", b)
	}
}
