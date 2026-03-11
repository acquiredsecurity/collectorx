package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bradleyroughan/forensic-collect/internal/collector"
	"github.com/bradleyroughan/forensic-collect/internal/output"
	"github.com/bradleyroughan/forensic-collect/internal/vss"
)

// --- Request / Response types ---

type collectRequest struct {
	Source     string   `json:"source"`
	Output     string   `json:"output"`
	Targets    []string `json:"targets"`
	CaseNumber string   `json:"caseNumber"`
	Operator   string   `json:"operator"`
	MaxSizeMB  uint64   `json:"maxSizeMB"`
	NoVSS      bool     `json:"noVSS"`
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
}

// --- Handlers ---

func (s *Server) handleGetTargets(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		name string
		desc string
	}

	var entries []entry
	for name, t := range s.Store.All() {
		entries = append(entries, entry{name, t.Description})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	// Mark well-known defaults
	defaults := map[string]bool{
		"KapeTriage.tkape": true,
	}

	var result []targetInfo
	for _, e := range entries {
		result = append(result, targetInfo{
			Name:        e.name,
			Description: e.desc,
			IsDefault:   defaults[e.name],
		})
	}

	writeJSON(w, result)
}

func (s *Server) handleGetProcessors(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Processors.List())
}

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
		targetNames = []string{"KapeTriage.tkape"}
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

	hostname := getHostname()
	timestamp := time.Now().UTC().Format("20060102_150405")
	stagingDir := filepath.Join(req.Output, fmt.Sprintf("staging_%s_%s", hostname, timestamp))
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		job.fail(fmt.Errorf("creating staging dir: %w", err))
		return
	}
	defer os.RemoveAll(stagingDir)

	// Create and configure collection engine
	engine := collector.NewEngine(req.Source, stagingDir)
	engine.UseVSS = !req.NoVSS && vss.Available()
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
		TotalFiles:  stats.FilesCollected,
		TotalBytes:  stats.BytesCollected,
		Pass1Files:  stats.Pass1Count,
		Pass2Files:  stats.Pass2Count,
		Pass3Files:  stats.Pass3Count,
		FailedFiles: stats.FilesFailed,
	})
	if err != nil {
		zipFile.Close()
		job.fail(fmt.Errorf("finalizing ZIP: %w", err))
		return
	}
	zipFile.Close()

	duration := manifest.CollectionEnd.Sub(manifest.CollectionStart)

	job.complete(map[string]any{
		"zipPath":        zipPath,
		"hostname":       manifest.Hostname,
		"filesCollected": stats.FilesCollected,
		"filesFailed":    stats.FilesFailed,
		"bytesCollected": stats.BytesCollected,
		"pass1":          stats.Pass1Count,
		"pass2":          stats.Pass2Count,
		"pass3":          stats.Pass3Count,
		"duration":       duration.Seconds(),
	})
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
