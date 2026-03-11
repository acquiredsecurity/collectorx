package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bradleyroughan/forensic-collect/internal/collector"
	"github.com/bradleyroughan/forensic-collect/internal/output"
	"github.com/bradleyroughan/forensic-collect/internal/server"
	"github.com/bradleyroughan/forensic-collect/internal/target"
	"github.com/bradleyroughan/forensic-collect/internal/vss"
)

// logWriter is a MultiWriter that tees to both console and log file.
var logWriter io.Writer = os.Stdout
var logErrWriter io.Writer = os.Stderr

// logf writes to both console and log file.
func logf(format string, args ...any) {
	fmt.Fprintf(logWriter, format, args...)
}

// logErrf writes to both stderr and log file.
func logErrf(format string, args ...any) {
	fmt.Fprintf(logErrWriter, format, args...)
}

const version = "0.5.0"

func main() {
	// CLI flags
	source := flag.String("source", "", "Source drive or mounted image/triage root directory")
	outputDir := flag.String("output", "", "Output directory for ZIP archive and manifest")
	targetsDir := flag.String("targets-dir", "./targets", "Path to targets directory containing .tkape files")
	collect := flag.String("collect", "", "Comma-separated target names (default: ForensicTriage)")
	maxSizeMB := flag.Uint64("max-size-mb", 0, "Maximum file size to collect in MB (0 = unlimited)")
	caseNumber := flag.String("case-number", "", "Case number for manifest")
	operator := flag.String("operator", "", "Operator name for manifest")
	noVSS := flag.Bool("no-vss", false, "Disable automatic VSS shadow copy for locked files")
	listTargets := flag.Bool("list-targets", false, "List all available targets and exit")
	dryRun := flag.Bool("dry-run", false, "Show what would be collected without copying")
	verbose := flag.Bool("v", false, "Verbose output")

	// Web UI flags
	serve := flag.Bool("serve", false, "Start the web UI server instead of CLI collection")
	port := flag.Int("port", 8080, "Web UI server port (used with --serve)")

	// Shorthands
	flag.StringVar(source, "s", "", "Source (shorthand)")
	flag.StringVar(outputDir, "o", "", "Output (shorthand)")
	flag.StringVar(targetsDir, "t", "./targets", "Targets dir (shorthand)")
	flag.StringVar(collect, "c", "", "Collect targets (shorthand)")

	flag.Parse()

	logf("forensic-collect v%s (Go)\n", version)

	// Set up log file in output directory (or current dir as fallback)
	logDir := *outputDir
	if logDir == "" {
		logDir = "."
	}
	if err := os.MkdirAll(logDir, 0o755); err == nil {
		logName := fmt.Sprintf("forensic-collect_%s.log", time.Now().UTC().Format("20060102_150405"))
		logPath := filepath.Join(logDir, logName)
		if lf, err := os.Create(logPath); err == nil {
			logWriter = io.MultiWriter(os.Stdout, lf)
			logErrWriter = io.MultiWriter(os.Stderr, lf)
			defer lf.Close()
			logf("Log file: %s\n", logPath)
		}
	}

	// Load target definitions
	logf("Loading targets from %s\n", *targetsDir)
	store, err := target.LoadTargetsFromDir(*targetsDir)
	if err != nil {
		fatal("Failed to load targets: %v", err)
	}
	if store.Len() == 0 {
		fatal("No .tkape target files found in %s", *targetsDir)
	}
	logf("Loaded %d target definitions\n", store.Len())

	// ===== Web UI mode =====
	if *serve {
		logf("Starting web UI on port %d\n", *port)
		srv := server.New(*port, *targetsDir, "", store)
		if err := srv.Start(); err != nil {
			fatal("Web server failed: %v", err)
		}
		return
	}

	// ===== CLI mode =====

	// List targets mode
	if *listTargets {
		logf("\nAvailable targets (%d):\n", store.Len())
		type entry struct {
			name string
			t    *target.TkapeTarget
		}
		var entries []entry
		for _, t := range store.All() {
			entries = append(entries, entry{t.Filename, t})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
		for _, e := range entries {
			compound := 0
			for _, t := range e.t.Targets {
				if t.IsCompound() {
					compound++
				}
			}
			direct := len(e.t.Targets) - compound
			logf("  %-40s %s (%d direct, %d compound refs)\n",
				e.name, e.t.Description, direct, compound)
		}
		return
	}

	if *source == "" {
		fatal("--source is required")
	}

	// Determine which targets to collect
	var targetNames []string
	if *collect != "" {
		for _, name := range strings.Split(*collect, ",") {
			name = strings.TrimSpace(name)
			if !strings.HasSuffix(name, ".tkape") {
				name += ".tkape"
			}
			targetNames = append(targetNames, name)
		}
	} else {
		targetNames = []string{"ForensicTriage.tkape"}
	}

	logf("Resolving targets: %v\n", targetNames)

	// Use shared resolution logic
	result, err := collector.ResolveCollectionItems(collector.ResolveConfig{
		SourceRoot:  *source,
		TargetNames: targetNames,
		Store:       store,
	})
	if err != nil {
		fatal("Failed to resolve targets: %v", err)
	}

	logf("Resolved %d concrete collection targets\n", result.ResolvedCount)
	logf("Discovered %d user profiles\n", result.UserProfiles)
	if len(result.Items) < result.PreDedupCount {
		logf("Deduplicated %d -> %d files (removed %d duplicates)\n",
			result.PreDedupCount, len(result.Items), result.PreDedupCount-len(result.Items))
	}

	items := result.Items
	logf("%d files queued for collection\n", len(items))

	// Verbose junction logging
	if *verbose {
		_ = verbose // suppress unused warning — verbose is used in the flag set
	}

	// Dry run mode
	if *dryRun {
		logf("\n=== Dry Run — %d files would be collected ===\n\n", len(items))
		for _, item := range items {
			logf("  [%s] %s -> %s\n", item.TargetName, item.SourcePath, item.DestRelPath)
		}
		return
	}

	if len(items) == 0 {
		logf("No files matched the target definitions. Nothing to collect.\n")
		return
	}

	if *outputDir == "" {
		fatal("--output is required for collection (only --list-targets and --dry-run can run without it)")
	}

	// Ensure output directory exists
	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		fatal("Cannot create output dir: %v", err)
	}

	// Create staging directory
	hostname := getHostname()
	timestamp := time.Now().UTC().Format("20060102_150405")

	stagingDir := filepath.Join(*outputDir, fmt.Sprintf("staging_%s_%s", hostname, timestamp))
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		fatal("Cannot create staging dir: %v", err)
	}

	// Run collection engine
	engine := collector.NewEngine(*source, stagingDir)
	engine.LogWriter = logWriter
	engine.ErrWriter = logErrWriter
	engine.UseVSS = !*noVSS && vss.Available()
	if *maxSizeMB > 0 {
		engine.MaxFileSize = *maxSizeMB * 1024 * 1024
	}

	logf("Locked files: raw NTFS (primary), VSS shadow copy (fallback)\n")

	collectedFiles, stats := engine.Collect(items)

	// Build ZIP output
	zipName := fmt.Sprintf("evidence_%s_%s.zip", hostname, timestamp)
	zipPath := filepath.Join(*outputDir, zipName)

	zipFile, err := os.Create(zipPath)
	if err != nil {
		fatal("Cannot create ZIP: %v", err)
	}

	ew := output.NewEvidenceWriter(zipFile, hostname, targetNames)
	if *operator != "" {
		ew.SetOperator(*operator)
	}
	if *caseNumber != "" {
		ew.SetCaseNumber(*caseNumber)
	}

	for _, cf := range collectedFiles {
		zipEntryPath := strings.ReplaceAll(cf.Item.DestRelPath, "\\", "/")

		hashes, err := ew.AddFile(zipEntryPath, cf.DestPath)
		if err != nil {
			logErrf("ERROR: adding to ZIP %s: %v\n", zipEntryPath, err)
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
		fatal("Failed to finalize ZIP: %v", err)
	}
	zipFile.Close()

	// Clean up staging directory
	os.RemoveAll(stagingDir)

	// Print summary
	duration := manifest.CollectionEnd.Sub(manifest.CollectionStart)
	logf("\n=== Collection Complete ===\n")
	logf("  Output:    %s\n", zipPath)
	logf("  Hostname:  %s\n", manifest.Hostname)
	logf("  Files:     %d collected, %d failed\n", stats.FilesCollected, stats.FilesFailed)
	logf("  Bytes:     %s\n", formatBytes(stats.BytesCollected))
	logf("  Pass 1:    %d files (normal copy)\n", stats.Pass1Count)
	if stats.Pass2Count > 0 {
		logf("  Pass 2:    %d files (raw NTFS)\n", stats.Pass2Count)
	}
	if stats.Pass3Count > 0 {
		logf("  Pass 3:    %d files (VSS shadow copy)\n", stats.Pass3Count)
	}
	logf("  Duration:  %.1fs\n", duration.Seconds())
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

func fatal(format string, args ...any) {
	logErrf("Error: "+format+"\n", args...)
	os.Exit(1)
}
