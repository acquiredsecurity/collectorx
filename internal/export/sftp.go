package export

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// sftpExporter uploads files via SCP/SFTP using the system ssh tools.
type sftpExporter struct {
	cfg     *SFTPConfig
	scpPath string
}

// NewSFTPExporter creates a new SSH/SCP exporter.
func NewSFTPExporter(cfg *SFTPConfig) (Exporter, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("SSH host is required")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("SSH username is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.RemotePath == "" {
		cfg.RemotePath = "."
	}

	scpPath, err := exec.LookPath("scp")
	if err != nil {
		return nil, fmt.Errorf("scp not found in PATH")
	}

	return &sftpExporter{cfg: cfg, scpPath: scpPath}, nil
}

func (e *sftpExporter) TestConnection() error {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found in PATH")
	}

	args := e.sshArgs()
	args = append(args, "-o", "ConnectTimeout=10", e.cfg.Username+"@"+e.cfg.Host, "echo ok")

	cmd := exec.Command(sshPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("SSH connection failed: %s — %v", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (e *sftpExporter) Upload(filePath string, onProgress ProgressFunc) (*Result, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", filePath, err)
	}

	fileName := filepath.Base(filePath)
	remoteDest := e.cfg.RemotePath
	if !strings.HasSuffix(remoteDest, "/") {
		remoteDest += "/"
	}
	remoteDest += fileName

	destination := fmt.Sprintf("%s@%s:%s", e.cfg.Username, e.cfg.Host, remoteDest)

	args := e.scpArgs()
	args = append(args, filePath, destination)

	cmd := exec.Command(e.scpPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("SCP upload failed: %s — %v", strings.TrimSpace(string(out)), err),
		}, err
	}

	if onProgress != nil {
		onProgress(info.Size(), info.Size())
	}

	return &Result{
		Success:   true,
		Message:   fmt.Sprintf("Uploaded to %s", destination),
		BytesSent: info.Size(),
	}, nil
}

// sshArgs builds common SSH options.
func (e *sftpExporter) sshArgs() []string {
	args := []string{"-o", "StrictHostKeyChecking=accept-new"}
	if e.cfg.Port != 22 {
		args = append(args, "-p", fmt.Sprintf("%d", e.cfg.Port))
	}
	if e.cfg.KeyPath != "" {
		args = append(args, "-i", e.cfg.KeyPath)
	}
	return args
}

// scpArgs builds SCP-specific arguments.
func (e *sftpExporter) scpArgs() []string {
	args := []string{"-o", "StrictHostKeyChecking=accept-new"}
	if e.cfg.Port != 22 {
		args = append(args, "-P", fmt.Sprintf("%d", e.cfg.Port))
	}
	if e.cfg.KeyPath != "" {
		args = append(args, "-i", e.cfg.KeyPath)
	}
	return args
}
