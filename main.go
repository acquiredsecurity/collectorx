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
	"github.com/bradleyroughan/forensic-collect/internal/export"
	"github.com/bradleyroughan/forensic-collect/internal/output"
	"github.com/bradleyroughan/forensic-collect/internal/pathresolver"
	"github.com/bradleyroughan/forensic-collect/internal/server"
	"github.com/bradleyroughan/forensic-collect/internal/target"
	"github.com/bradleyroughan/forensic-collect/internal/vss"
	"gopkg.in/yaml.v3"
)

// Config represents a YAML collection profile.
type Config struct {
	Source         string   `yaml:"source"`
	Output         string   `yaml:"output"`
	Platform       string   `yaml:"platform"`
	CaseNumber     string   `yaml:"case_number"`
	Operator       string   `yaml:"operator"`
	Hostname       string   `yaml:"hostname"`
	Targets        []string `yaml:"targets"`
	OutputFormat   string   `yaml:"output_format"`
	VHDSize        string   `yaml:"vhd_size"`
	VHDFS          string   `yaml:"vhd_fs"`
	ContentCollect bool     `yaml:"content_collect"`
	ContentPresets []string `yaml:"content_presets"`
	MaxSizeMB      uint64       `yaml:"max_size_mb"`
	NoVSS          bool         `yaml:"no_vss"`
	TargetsDir     string       `yaml:"targets_dir"`
	Export         ExportConfig `yaml:"export"`
}

// ExportConfig holds post-collection upload settings.
type ExportConfig struct {
	Type      string `yaml:"type"`       // "s3", "sftp", "ftp", or ""
	Bucket    string `yaml:"bucket"`     // S3 bucket name
	Region    string `yaml:"region"`     // S3 region (default: us-east-1)
	Prefix    string `yaml:"prefix"`     // S3 key prefix (folder path)
	AccessKey string `yaml:"access_key"` // AWS access key (write-only IAM recommended)
	SecretKey string `yaml:"secret_key"` // AWS secret key
	Endpoint  string `yaml:"endpoint"`   // Custom S3 endpoint (MinIO, Wasabi, etc.)
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return &cfg, nil
}

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

const version = "0.6.0"

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `forensic-collect v%s — Fast forensic artifact collector

USAGE:
  forensic-collect [flags]

EXAMPLES:
  # Collect default triage from C: drive (ForensicTriage on Windows)
  forensic-collect.exe -s C:\ -o D:\output

  # Collect with case metadata
  forensic-collect.exe -s C:\ -o D:\output --case-number IR-2026-042 --operator jdoe

  # Collect specific targets
  forensic-collect.exe -s C:\ -o D:\output -c "EventLogs,RegistryHives,Prefetch"

  # Output as both ZIP and NTFS VHD
  forensic-collect.exe -s C:\ -o D:\output --output-format both --vhd-fs ntfs

  # Output as ExFAT VHD (mountable on macOS and Windows)
  forensic-collect.exe -s C:\ -o D:\output --output-format vhd --vhd-fs exfat

  # Content collection — grab all Office docs and archives
  forensic-collect.exe -s C:\ -o D:\output --content-preset "office-docs,archives"

  # Content collection — custom file filter
  forensic-collect.exe -s C:\ -o D:\output --content-collect --search-path "C:\Users" \
    --file-filter "*.docx,*.xlsx,*.pdf" --modified-after 2025-01-01

  # Use a YAML config file
  forensic-collect.exe --config incident-response.yaml

  # Use config but override source
  forensic-collect.exe --config incident-response.yaml -s E:\

  # Dry run — see what would be collected
  forensic-collect.exe -s C:\ --dry-run

  # List all available targets
  forensic-collect.exe --list-targets

  # Collect from mounted forensic image
  forensic-collect.exe -s E:\ -o D:\output --platform windows

  # Start web UI
  forensic-collect.exe --serve --port 8080

  # Browse VSS shadow copies
  forensic-collect.exe --vss-browse

  # Collect from all VSS snapshots
  forensic-collect.exe -s C:\ -o D:\output --vss-collect-all

FLAGS:
`, version)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
CONTENT PRESETS:
  recycle-bin       Recycle Bin contents
  archives          ZIP, RAR, 7z, TAR, GZ archives
  office-docs       Word, Excel, PowerPoint, PDF files
  email-stores      PST, OST, EML, MBOX email files
  databases         SQLite, Access, SQL Server files
  scripts           PowerShell, Batch, Python, VBS scripts
  user-documents    Documents from user profile folders

CONFIG FILE:
  Save collection profiles as YAML files. CLI flags override config values.
  See README for full config file format.
`)
	}

	// CLI flags
	source := flag.String("source", "", "Source drive or mounted image/triage root directory")
	outputDir := flag.String("output", "", "Output directory for ZIP archive and manifest")
	targetsDir := flag.String("targets-dir", "./targets", "Path to targets directory containing .tkape files")
	collect := flag.String("collect", "", "Comma-separated target names (default: platform-specific triage)")
	maxSizeMB := flag.Uint64("max-size-mb", 0, "Maximum file size to collect in MB (0 = unlimited)")
	caseNumber := flag.String("case-number", "", "Case number for manifest")
	operator := flag.String("operator", "", "Operator name for manifest")
	hostnameFlag := flag.String("hostname", "", "Evidence hostname (auto-detected from source if empty)")
	noVSS := flag.Bool("no-vss", false, "Disable automatic VSS shadow copy for locked files")
	listTargets := flag.Bool("list-targets", false, "List all available targets and exit")
	dryRun := flag.Bool("dry-run", false, "Show what would be collected without copying")
	verbose := flag.Bool("v", false, "Verbose output")

	// Platform flag
	platformFlag := flag.String("platform", "", "Target platform: windows, mac, linux (auto-detected if empty)")

	// Content collection flags
	contentCollect := flag.Bool("content-collect", false, "Enable content collection mode (file path + filter)")
	searchPath := flag.String("search-path", "", "Root path to search for content collection")
	fileFilter := flag.String("file-filter", "", "Comma-separated file glob filters (e.g., '*.zip,*.docx')")
	excludePath := flag.String("exclude-path", "", "Comma-separated path patterns to exclude")
	maxDepth := flag.Int("max-depth", 0, "Maximum recursion depth for content collection (0 = unlimited)")
	minSizeBytes := flag.Uint64("min-size", 0, "Minimum file size in bytes for content collection")
	maxSizeBytes := flag.Uint64("max-size", 0, "Maximum file size in bytes for content collection")
	modifiedAfter := flag.String("modified-after", "", "Only collect files modified after this date (YYYY-MM-DD)")
	modifiedBefore := flag.String("modified-before", "", "Only collect files modified before this date (YYYY-MM-DD)")
	contentPreset := flag.String("content-preset", "", "Built-in content preset: recycle-bin, archives, office-docs, email-stores, databases, scripts, user-documents")

	// VSS browsing flags
	vssBrowse := flag.Bool("vss-browse", false, "List all available VSS shadow copies and exit")
	vssCollectAll := flag.Bool("vss-collect-all", false, "Collect artifacts from all existing shadow copies")

	// Output format flags
	outputFormat := flag.String("output-format", "zip", "Output format: zip, vhd, both (vhd only for Windows collections)")
	vhdSize := flag.String("vhd-size", "auto", "VHD disk size (e.g., '10G', '50G', 'auto')")
	vhdFS := flag.String("vhd-fs", "auto", "VHD filesystem: ntfs, exfat, auto (auto=NTFS on Windows, ExFAT elsewhere)")

	// Web UI flags
	serve := flag.Bool("serve", false, "Start the web UI server instead of CLI collection")
	port := flag.Int("port", 8080, "Web UI server port (used with --serve)")

	// Export flags (post-collection upload)
	exportType := flag.String("export", "", "Export type: s3, sftp, ftp (uploads output after collection)")
	s3Bucket := flag.String("s3-bucket", "", "S3 bucket name for export")
	s3Region := flag.String("s3-region", "us-east-1", "S3 region")
	s3Prefix := flag.String("s3-prefix", "", "S3 key prefix/folder (e.g., cases/IR-2026-042/)")
	s3AccessKey := flag.String("s3-access-key", "", "AWS access key (or use AWS_ACCESS_KEY_ID env var)")
	s3SecretKey := flag.String("s3-secret-key", "", "AWS secret key (or use AWS_SECRET_ACCESS_KEY env var)")
	s3Endpoint := flag.String("s3-endpoint", "", "Custom S3 endpoint for MinIO/Wasabi/etc.")

	// Config file flag
	configFile := flag.String("config", "", "Load collection profile from YAML config file")

	// Shorthands
	flag.StringVar(source, "s", "", "Source (shorthand)")
	flag.StringVar(outputDir, "o", "", "Output (shorthand)")
	flag.StringVar(targetsDir, "t", "./targets", "Targets dir (shorthand)")
	flag.StringVar(collect, "c", "", "Collect targets (shorthand)")

	flag.Parse()

	// Apply config file defaults — CLI flags override config values
	if *configFile != "" {
		cfg, err := loadConfig(*configFile)
		if err != nil {
			fatal("%v", err)
		}
		logf("Loaded config: %s\n", *configFile)

		// Track which flags were explicitly set on the command line
		setFlags := make(map[string]bool)
		flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

		// Apply config values only where the CLI flag was NOT explicitly set
		if cfg.Source != "" && !setFlags["source"] && !setFlags["s"] {
			*source = cfg.Source
		}
		if cfg.Output != "" && !setFlags["output"] && !setFlags["o"] {
			*outputDir = cfg.Output
		}
		if cfg.Platform != "" && !setFlags["platform"] {
			*platformFlag = cfg.Platform
		}
		if cfg.CaseNumber != "" && !setFlags["case-number"] {
			*caseNumber = cfg.CaseNumber
		}
		if cfg.Operator != "" && !setFlags["operator"] {
			*operator = cfg.Operator
		}
		if cfg.Hostname != "" && !setFlags["hostname"] {
			*hostnameFlag = cfg.Hostname
		}
		if len(cfg.Targets) > 0 && !setFlags["collect"] && !setFlags["c"] {
			*collect = strings.Join(cfg.Targets, ",")
		}
		if cfg.OutputFormat != "" && !setFlags["output-format"] {
			*outputFormat = cfg.OutputFormat
		}
		if cfg.VHDSize != "" && !setFlags["vhd-size"] {
			*vhdSize = cfg.VHDSize
		}
		if cfg.VHDFS != "" && !setFlags["vhd-fs"] {
			*vhdFS = cfg.VHDFS
		}
		if cfg.ContentCollect && !setFlags["content-collect"] {
			*contentCollect = true
		}
		if len(cfg.ContentPresets) > 0 && !setFlags["content-preset"] {
			*contentPreset = strings.Join(cfg.ContentPresets, ",")
		}
		if cfg.MaxSizeMB > 0 && !setFlags["max-size-mb"] {
			*maxSizeMB = cfg.MaxSizeMB
		}
		if cfg.NoVSS && !setFlags["no-vss"] {
			*noVSS = true
		}
		if cfg.TargetsDir != "" && !setFlags["targets-dir"] && !setFlags["t"] {
			*targetsDir = cfg.TargetsDir
		}
		// Apply export config from YAML
		if cfg.Export.Type != "" && !setFlags["export"] {
			*exportType = cfg.Export.Type
		}
		if cfg.Export.Bucket != "" && !setFlags["s3-bucket"] {
			*s3Bucket = cfg.Export.Bucket
		}
		if cfg.Export.Region != "" && !setFlags["s3-region"] {
			*s3Region = cfg.Export.Region
		}
		if cfg.Export.Prefix != "" && !setFlags["s3-prefix"] {
			*s3Prefix = cfg.Export.Prefix
		}
		if cfg.Export.AccessKey != "" && !setFlags["s3-access-key"] {
			*s3AccessKey = cfg.Export.AccessKey
		}
		if cfg.Export.SecretKey != "" && !setFlags["s3-secret-key"] {
			*s3SecretKey = cfg.Export.SecretKey
		}
		if cfg.Export.Endpoint != "" && !setFlags["s3-endpoint"] {
			*s3Endpoint = cfg.Export.Endpoint
		}
	}

	logf("forensic-collect v%s (Go)\n", version)

	// Detect platform
	platform := pathresolver.ParsePlatform(*platformFlag)
	logf("Platform: %s\n", platform)

	// Set up log file in output directory (or current dir as fallback)
	logDir := *outputDir
	if logDir == "" {
		logDir = "."
	}
	var collectionLogPath string
	var collectionLogFile *os.File
	if err := os.MkdirAll(logDir, 0o755); err == nil {
		logName := fmt.Sprintf("forensic-collect_%s.log", time.Now().UTC().Format("20060102_150405"))
		collectionLogPath = filepath.Join(logDir, logName)
		if lf, err := os.Create(collectionLogPath); err == nil {
			collectionLogFile = lf
			logWriter = io.MultiWriter(os.Stdout, lf)
			logErrWriter = io.MultiWriter(os.Stderr, lf)
			defer lf.Close()
			logf("Log file: %s\n", collectionLogPath)
		}
	}

	// ===== VSS Browse mode =====
	if *vssBrowse {
		if !vss.Available() {
			fatal("VSS browsing is only available on Windows")
		}
		shadows, err := vss.ListShadows()
		if err != nil {
			fatal("Failed to list shadow copies: %v", err)
		}
		if len(shadows) == 0 {
			logf("No VSS shadow copies found.\n")
			return
		}
		logf("\nAvailable VSS Shadow Copies:\n")
		for _, s := range shadows {
			logf("  ID: %s\n    Device: %s\n    Volume: %s\n    Created: %s\n\n",
				s.ID, s.DevicePath, s.VolumeName, s.CreationTime.Format(time.RFC3339))
		}
		return
	}

	// Determine targets directory based on platform
	effectiveTargetsDir := *targetsDir
	if subdir := platform.TargetsSubdir(); subdir != "" {
		platformDir := filepath.Join(*targetsDir, subdir)
		if info, err := os.Stat(platformDir); err == nil && info.IsDir() {
			effectiveTargetsDir = platformDir
		}
	}

	// Load target definitions
	logf("Loading targets from %s\n", effectiveTargetsDir)
	store, err := target.LoadTargetsFromDir(effectiveTargetsDir)
	if err != nil {
		fatal("Failed to load targets: %v", err)
	}
	if store.Len() == 0 {
		fatal("No .tkape target files found in %s", effectiveTargetsDir)
	}
	logf("Loaded %d target definitions\n", store.Len())

	// ===== Web UI mode =====
	if *serve {
		logf("Starting web UI on port %d\n", *port)
		srv := server.New(*port, effectiveTargetsDir, "", store, platform)
		if err := srv.Start(); err != nil {
			fatal("Web server failed: %v", err)
		}
		return
	}

	// ===== CLI mode =====

	// List targets mode
	if *listTargets {
		logf("\nAvailable targets (%d) for platform %s:\n", store.Len(), platform)
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

	// Resolve symlinks in source path (e.g. macOS /tmp -> /private/tmp)
	// so that all relative path calculations are consistent
	if resolved, err := filepath.EvalSymlinks(*source); err == nil {
		*source = resolved
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
	} else if !*contentCollect && *contentPreset == "" {
		// Use platform default if no content-collect mode
		targetNames = []string{platform.DefaultTriageTarget()}
	}

	// Build collection items from targets
	var items []collector.CollectionItem

	if len(targetNames) > 0 {
		logf("Resolving targets: %v\n", targetNames)

		result, err := collector.ResolveCollectionItems(collector.ResolveConfig{
			SourceRoot:  *source,
			TargetNames: targetNames,
			Store:       store,
			Platform:    platform,
			LogWriter:   logWriter,
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
		items = append(items, result.Items...)
	}

	// Content collection mode
	if *contentCollect || *contentPreset != "" {
		var filters []collector.ContentFilter

		if *contentPreset != "" {
			presets := collector.ContentPresets()
			for _, presetName := range strings.Split(*contentPreset, ",") {
				presetName = strings.TrimSpace(presetName)
				if preset, ok := presets[presetName]; ok {
					logf("Using content preset: %s\n", presetName)
					filters = append(filters, preset)
				} else {
					logErrf("WARN: unknown content preset %q (available: recycle-bin, archives, office-docs, email-stores, databases, scripts, user-documents)\n", presetName)
				}
			}
		}

		if *searchPath != "" && *fileFilter != "" {
			filter := collector.ContentFilter{
				SearchPath:  *searchPath,
				FileFilters: collector.ParseFileFilters(*fileFilter),
				MaxDepth:    *maxDepth,
				MinSize:     *minSizeBytes,
				MaxSize:     *maxSizeBytes,
			}
			if *excludePath != "" {
				filter.ExcludePaths = collector.ParseFileFilters(*excludePath)
			}
			if *modifiedAfter != "" {
				if t, err := time.Parse("2006-01-02", *modifiedAfter); err == nil {
					filter.ModifiedAfter = &t
				}
			}
			if *modifiedBefore != "" {
				if t, err := time.Parse("2006-01-02", *modifiedBefore); err == nil {
					filter.ModifiedBefore = &t
				}
			}
			filters = append(filters, filter)
		}

		for _, filter := range filters {
			contentItems := collector.ResolveContentFilter(filter, *source)
			logf("Content filter matched %d files\n", len(contentItems))
			items = append(items, contentItems...)
		}
	}

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
		fatal("--output is required for collection (only --list-targets, --dry-run, and --vss-browse can run without it)")
	}

	// Ensure output directory exists
	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		fatal("Cannot create output dir: %v", err)
	}

	// Determine hostname — prefer explicit flag, then auto-detect from evidence, then local
	hostname := *hostnameFlag
	if hostname == "" {
		hostname = detectEvidenceHostname(*source, platform)
	}
	if hostname == "" {
		hostname = getHostname()
	}
	timestamp := time.Now().UTC().Format("20060102_150405")

	stagingDir := filepath.Join(*outputDir, fmt.Sprintf("staging_%s_%s", hostname, timestamp))
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		fatal("Cannot create staging dir: %v", err)
	}

	// Collect from existing VSS snapshots if requested
	if *vssCollectAll && vss.Available() {
		shadows, err := vss.ListShadows()
		if err != nil {
			logErrf("WARN: failed to list shadow copies: %v\n", err)
		} else {
			logf("Found %d existing shadow copies, collecting from each...\n", len(shadows))
			for _, shadow := range shadows {
				shadowRoot := vss.CollectFromShadow(shadow)
				if shadowRoot == "" {
					continue
				}
				logf("Collecting from shadow %s (created %s)...\n", shadow.ID, shadow.CreationTime.Format(time.RFC3339))

				if len(targetNames) > 0 {
					shadowResult, err := collector.ResolveCollectionItems(collector.ResolveConfig{
						SourceRoot:  shadowRoot,
						TargetNames: targetNames,
						Store:       store,
						Platform:    platform,
						LogWriter:   logWriter,
					})
					if err == nil {
						shortID := shadow.ID
						if len(shortID) > 8 {
							shortID = shortID[:8]
						}
						for _, item := range shadowResult.Items {
							item.DestRelPath = filepath.Join("VSS_Snapshots", shortID, item.DestRelPath)
							items = append(items, item)
						}
						logf("  Shadow %s: %d additional files\n", shortID, len(shadowResult.Items))
					}
				}
			}
		}
	}

	// Run collection engine
	engine := collector.NewEngine(*source, stagingDir)
	engine.LogWriter = logWriter
	engine.ErrWriter = logErrWriter
	if *maxSizeMB > 0 {
		engine.MaxFileSize = *maxSizeMB * 1024 * 1024
	}

	if platform == pathresolver.PlatformWindows {
		logf("Collection mode: smart routing (normal copy + raw NTFS for locked files)\n")
	} else {
		logf("Collection mode: normal copy (platform: %s)\n", platform)
	}

	collectedFiles, stats := engine.Collect(items)

	// Determine output format
	format := strings.ToLower(*outputFormat)
	createZip := format == "zip" || format == "both"
	createVHD := format == "vhd" || format == "both"

	// VHD output is only supported for Windows collections
	if createVHD && platform != pathresolver.PlatformWindows {
		logf("WARN: VHD output is only supported for Windows collections — falling back to ZIP\n")
		createVHD = false
		createZip = true
	}

	if !createZip && !createVHD {
		createZip = true // default to zip
	}

	// Bundle the collection log into the staging directory so it's included in the ZIP
	if collectionLogFile != nil && collectionLogPath != "" {
		collectionLogFile.Sync()
		logDest := filepath.Join(stagingDir, "collection.log")
		if src, err := os.Open(collectionLogPath); err == nil {
			if dst, err := os.Create(logDest); err == nil {
				io.Copy(dst, src)
				dst.Close()
			}
			src.Close()
		}
	}

	var zipPath string

	if createZip {
		// Build ZIP output
		zipName := fmt.Sprintf("evidence_%s_%s.zip", hostname, timestamp)
		zipPath = filepath.Join(*outputDir, zipName)

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
		ew.SetPlatform(string(platform))
		ew.SetOutputFormat(format)

		for _, cf := range collectedFiles {
			zipEntryPath := strings.ReplaceAll(cf.Item.DestRelPath, "\\", "/")

			hashes, err := ew.AddFile(zipEntryPath, cf.DestPath)
			if err != nil {
				logErrf("ERROR: adding to ZIP %s: %v\n", zipEntryPath, err)
				continue
			}

			entry := output.ManifestEntry{
				SourcePath:   cf.Item.SourcePath,
				DestPath:     zipEntryPath,
				SizeBytes:    hashes.SizeBytes,
				MD5:          hashes.MD5,
				SHA256:       hashes.SHA256,
				CollectedVia: cf.Method,
				TargetName:   cf.Item.TargetName,
			}
			if cf.Item.Category == "ContentCollection" {
				entry.FilterMatched = cf.Item.TargetName
			}

			ew.RecordEntry(entry)
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
			fatal("Failed to finalize ZIP: %v", err)
		}
		zipFile.Close()

		duration := manifest.CollectionEnd.Sub(manifest.CollectionStart)
		logf("\n=== Collection Complete ===\n")
		logf("  Output:    %s\n", zipPath)
		logf("  Platform:  %s\n", platform)
		logf("  Hostname:  %s\n", manifest.Hostname)
		logf("  Files:     %d collected, %d failed\n", stats.FilesCollected, stats.FilesFailed)
		logf("  Bytes:     %s\n", formatBytes(stats.BytesCollected))
		logf("  Normal:    %d files\n", stats.NormalCount)
		if stats.RawNTFSCount > 0 {
			logf("  Raw NTFS:  %d files (locked/metafiles)\n", stats.RawNTFSCount)
		}
		logf("  Duration:  %.1fs\n", duration.Seconds())
	}

	if createVHD {
		logf("\nCreating VHD output...\n")
		vhdName := fmt.Sprintf("evidence_%s_%s", hostname, timestamp)
		vhdWriter := output.NewVHDWriter(*outputDir, *vhdSize, *vhdFS)
		vhdPath, err := vhdWriter.CreateFromDirectory(stagingDir, vhdName, logWriter)
		if err != nil {
			logErrf("ERROR: VHD creation failed: %v\n", err)
			if !createZip {
				fatal("VHD creation failed and no ZIP fallback: %v", err)
			}
		} else {
			logf("  VHD:       %s\n", vhdPath)
		}
	}

	// Export to remote destination if configured
	if *exportType != "" {
		logf("\n=== Exporting to %s ===\n", *exportType)

		var exportCfg *export.Config
		switch *exportType {
		case "s3":
			if *s3Bucket == "" {
				logErrf("ERROR: --s3-bucket is required for S3 export\n")
			} else {
				exportCfg = &export.Config{
					Type: "s3",
					S3: &export.S3Config{
						Bucket:    *s3Bucket,
						Region:    *s3Region,
						Prefix:    *s3Prefix,
						AccessKey: *s3AccessKey,
						SecretKey: *s3SecretKey,
						Endpoint:  *s3Endpoint,
					},
				}
			}
		default:
			logErrf("ERROR: unsupported export type: %s\n", *exportType)
		}

		if exportCfg != nil {
			exporter, err := export.New(exportCfg)
			if err != nil {
				logErrf("ERROR: failed to create exporter: %v\n", err)
			} else {
				logf("  Testing connection...\n")
				if err := exporter.TestConnection(); err != nil {
					logErrf("ERROR: export connection test failed: %v\n", err)
				} else {
					// Upload the ZIP if it exists
					if createZip {
						zipInfo, _ := os.Stat(zipPath)
						totalMB := float64(0)
						if zipInfo != nil {
							totalMB = float64(zipInfo.Size()) / (1024 * 1024)
						}
						logf("  Uploading %s (%.1f MB)...\n", filepath.Base(zipPath), totalMB)
						uploadStart := time.Now()
						result, err := exporter.Upload(zipPath, func(sent, total int64) {
							pct := float64(sent) / float64(total) * 100
							sentMB := float64(sent) / (1024 * 1024)
							totalMB := float64(total) / (1024 * 1024)
							elapsed := time.Since(uploadStart).Seconds()
							speedMBs := sentMB / elapsed
							remaining := ""
							if speedMBs > 0 && pct < 100 {
								etaSec := (totalMB - sentMB) / speedMBs
								if etaSec < 60 {
									remaining = fmt.Sprintf("~%.0fs remaining", etaSec)
								} else {
									remaining = fmt.Sprintf("~%.0fm remaining", etaSec/60)
								}
							}
							// Progress bar
							barWidth := 30
							filled := int(pct / 100 * float64(barWidth))
							bar := strings.Repeat("#", filled) + strings.Repeat("-", barWidth-filled)
							fmt.Fprintf(logWriter, "\r  [%s] %.1f%% — %.0f/%.0f MB — %.1f MB/s — %s    ", bar, pct, sentMB, totalMB, speedMBs, remaining)
						})
						fmt.Fprintf(logWriter, "\n")
						if err != nil {
							logErrf("ERROR: upload failed: %v\n", err)
						} else {
							logf("  %s (%s)\n", result.Message, formatBytes(uint64(result.BytesSent)))
						}
					}
				}
			}
		}
	}

	// Clean up staging directory
	os.RemoveAll(stagingDir)
}

func getHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "UNKNOWN"
	}
	return h
}

// detectEvidenceHostname tries to determine the hostname of the evidence source.
// For Windows: reads ComputerName from the SYSTEM registry hive on disk.
// Falls back to deriving a name from the source path.
func detectEvidenceHostname(sourceRoot string, platform pathresolver.Platform) string {
	if platform == pathresolver.PlatformWindows {
		if name := readWindowsComputerName(sourceRoot); name != "" {
			return name
		}
	}

	// Fall back: derive from source path
	// e.g., /tmp/mnt_win11 → "mnt_win11", /Volumes/stuff/forensic_images/Magnet_Win11 → "Magnet_Win11"
	base := filepath.Base(sourceRoot)
	if base != "" && base != "." && base != "/" && base != "\\" {
		// Clean up: replace spaces with underscores
		return strings.ReplaceAll(base, " ", "_")
	}
	return ""
}

// readWindowsComputerName reads the ComputerName value from the SYSTEM registry hive.
// It scans the raw hive binary for the ASCII "ComputerName" key name followed by the
// UTF-16LE hostname value.
func readWindowsComputerName(sourceRoot string) string {
	// Try common SYSTEM hive locations
	candidates := []string{
		filepath.Join(sourceRoot, "Windows", "System32", "config", "SYSTEM"),
		filepath.Join(sourceRoot, "windows", "system32", "config", "SYSTEM"),
		filepath.Join(sourceRoot, "Windows", "System32", "config", "system"),
	}

	// Also try case-insensitive search
	configDir := filepath.Join(sourceRoot, "Windows", "System32", "config")
	if entries, err := os.ReadDir(configDir); err == nil {
		for _, e := range entries {
			if strings.EqualFold(e.Name(), "system") && !e.IsDir() {
				candidates = append(candidates, filepath.Join(configDir, e.Name()))
			}
		}
	}

	for _, path := range candidates {
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		// Read the full hive (ComputerName can be anywhere)
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			continue
		}

		if name := extractComputerName(data); name != "" {
			return name
		}
	}
	return ""
}

// extractComputerName scans a raw SYSTEM registry hive for the ComputerName value.
// Registry key/value names are stored as ASCII. The value data (the actual hostname)
// is stored as UTF-16LE in a nearby cell. We look for the specific pattern:
// "ComputerName" (ASCII) + flags + cell_size(0xFFFFxxxx) + UTF-16LE hostname data.
func extractComputerName(data []byte) string {
	needle := []byte("ComputerName")
	var bestName string

	for i := 0; i < len(data)-len(needle)-60; i++ {
		if data[i] != 'C' || !bytesEqual(data[i:i+len(needle)], needle) {
			continue
		}

		// Scan the next 256 bytes for an allocated registry cell (0xFFFFxxxx size)
		// followed by UTF-16LE hostname data
		searchEnd := i + 256
		if searchEnd > len(data) {
			searchEnd = len(data)
		}

		for j := i + len(needle); j < searchEnd-34; j++ {
			// Look for cell size marker: byte pattern xx FF FF FF (allocated cell, little-endian negative)
			if j+4 < searchEnd && data[j+1] == 0xFF && data[j+2] == 0xFF && data[j+3] == 0xFF {
				// UTF-16LE hostname should start right after the 4-byte cell size
				start := j + 4
				if start+30 <= len(data) {
					if name := tryReadUTF16LEHostname(data[start : start+32]); name != "" {
						// Prefer longer names (more specific)
						if len(name) > len(bestName) {
							bestName = name
						}
					}
				}
			}
		}
	}
	return bestName
}

// tryReadUTF16LEHostname tries to read a valid Windows hostname from UTF-16LE data.
func tryReadUTF16LEHostname(data []byte) string {
	if len(data) < 4 {
		return ""
	}

	var chars []byte
	for i := 0; i+1 < len(data) && i < 30; i += 2 {
		lo, hi := data[i], data[i+1]
		if hi != 0 {
			break // Not ASCII UTF-16LE
		}
		if lo == 0 {
			break // Null terminator
		}
		// Valid hostname chars: A-Z, a-z, 0-9, -
		if (lo >= 'A' && lo <= 'Z') || (lo >= 'a' && lo <= 'z') || (lo >= '0' && lo <= '9') || lo == '-' {
			chars = append(chars, lo)
		} else {
			return "" // Invalid character
		}
	}

	name := string(chars)
	// Windows hostnames are typically 3-15 characters (DESKTOP-xxx, PC-xxx, etc.)
	// Require at least 3 to avoid false positives from stray bytes
	if len(name) >= 3 && len(name) <= 15 {
		return strings.ToUpper(name)
	}
	return ""
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
