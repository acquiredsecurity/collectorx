// Package export provides post-collection file upload to remote destinations.
package export

import (
	"fmt"
	"io"
)

// Config holds the export destination configuration.
type Config struct {
	Type string      `json:"type"` // "s3", "sftp", "ftp", or ""
	S3   *S3Config   `json:"s3,omitempty"`
	SFTP *SFTPConfig `json:"sftp,omitempty"`
	FTP  *FTPConfig  `json:"ftp,omitempty"`
}

// S3Config holds Amazon S3 (or S3-compatible) upload settings.
type S3Config struct {
	Bucket    string `json:"bucket"`
	Region    string `json:"region"`
	Prefix    string `json:"prefix"`    // key prefix (folder path)
	AccessKey string `json:"accessKey"` // leave empty to use default credentials
	SecretKey string `json:"secretKey"`
	Endpoint  string `json:"endpoint"` // custom endpoint for MinIO, Wasabi, etc.
}

// SFTPConfig holds SSH/SCP upload settings.
type SFTPConfig struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`   // password auth
	KeyPath    string `json:"keyPath"`     // path to SSH private key
	RemotePath string `json:"remotePath"` // destination directory on remote
}

// FTPConfig holds FTP upload settings.
type FTPConfig struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	RemotePath string `json:"remotePath"`
	UseTLS     bool   `json:"useTLS"` // explicit FTPS (AUTH TLS)
}

// Result holds the outcome of an export operation.
type Result struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	BytesSent int64  `json:"bytesSent"`
}

// ProgressFunc is called during upload with bytes sent and total bytes.
type ProgressFunc func(bytesSent, totalBytes int64)

// Exporter uploads a file to a remote destination.
type Exporter interface {
	Upload(filePath string, onProgress ProgressFunc) (*Result, error)
	TestConnection() error
}

// New creates an Exporter from the given config.
func New(cfg *Config) (Exporter, error) {
	switch cfg.Type {
	case "s3":
		if cfg.S3 == nil {
			return nil, fmt.Errorf("S3 config is required")
		}
		return NewS3Exporter(cfg.S3)
	case "sftp":
		if cfg.SFTP == nil {
			return nil, fmt.Errorf("SFTP config is required")
		}
		return NewSFTPExporter(cfg.SFTP)
	case "ftp":
		if cfg.FTP == nil {
			return nil, fmt.Errorf("FTP config is required")
		}
		return NewFTPExporter(cfg.FTP)
	default:
		return nil, fmt.Errorf("unknown export type: %q", cfg.Type)
	}
}

// countingReader wraps a reader and counts bytes read.
type countingReader struct {
	r          io.Reader
	bytesRead  int64
	totalBytes int64
	onProgress ProgressFunc
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.bytesRead += int64(n)
	if cr.onProgress != nil && n > 0 {
		cr.onProgress(cr.bytesRead, cr.totalBytes)
	}
	return n, err
}
