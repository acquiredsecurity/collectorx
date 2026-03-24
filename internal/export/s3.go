package export

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// s3Exporter uploads files to S3 using native HTTP with AWS Signature V4.
// No AWS CLI or SDK required — fully portable.
type s3Exporter struct {
	cfg *S3Config
}

// NewS3Exporter creates a new S3 exporter using native HTTP.
func NewS3Exporter(cfg *S3Config) (Exporter, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("S3 bucket is required")
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	// Fall back to environment variables for credentials
	if cfg.AccessKey == "" {
		cfg.AccessKey = os.Getenv("AWS_ACCESS_KEY_ID")
	}
	if cfg.SecretKey == "" {
		cfg.SecretKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, fmt.Errorf("S3 credentials required: set access_key/secret_key in config or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY env vars")
	}
	return &s3Exporter{cfg: cfg}, nil
}

func (e *s3Exporter) TestConnection() error {
	// ListBucket with max-keys=1 to verify credentials and bucket access
	endpoint := e.endpoint()
	url := fmt.Sprintf("%s/?list-type=2&max-keys=1", endpoint)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	e.signRequest(req, nil)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("S3 connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("S3 returned %d: %s", resp.StatusCode, string(body[:min(len(body), 500)]))
	}
	return nil
}

func (e *s3Exporter) Upload(filePath string, onProgress ProgressFunc) (*Result, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", filePath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", filePath, err)
	}

	fileName := filepath.Base(filePath)
	s3Key := fileName
	if e.cfg.Prefix != "" {
		s3Key = strings.TrimSuffix(e.cfg.Prefix, "/") + "/" + fileName
	}

	endpoint := e.endpoint()
	url := fmt.Sprintf("%s/%s", endpoint, s3Key)

	// Wrap reader with progress tracking
	var reader io.Reader = f
	if onProgress != nil {
		reader = &progressReader{
			reader:     f,
			total:      info.Size(),
			onProgress: onProgress,
		}
	}

	req, err := http.NewRequest("PUT", url, reader)
	if err != nil {
		return nil, fmt.Errorf("creating upload request: %w", err)
	}
	req.ContentLength = info.Size()
	req.Header.Set("Content-Type", "application/zip")

	// For PUT with body, we sign with UNSIGNED-PAYLOAD to avoid reading the file twice
	e.signRequestUnsignedPayload(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("S3 upload failed: %v", err),
		}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return &Result{
			Success: false,
			Message: fmt.Sprintf("S3 upload failed (%d): %s", resp.StatusCode, string(body[:min(len(body), 500)])),
		}, fmt.Errorf("S3 returned %d", resp.StatusCode)
	}

	return &Result{
		Success:   true,
		Message:   fmt.Sprintf("Uploaded to s3://%s/%s", e.cfg.Bucket, s3Key),
		BytesSent: info.Size(),
	}, nil
}

// endpoint returns the S3 endpoint URL for the bucket.
func (e *s3Exporter) endpoint() string {
	if e.cfg.Endpoint != "" {
		return strings.TrimSuffix(e.cfg.Endpoint, "/") + "/" + e.cfg.Bucket
	}
	// Standard AWS S3 path-style URL
	return fmt.Sprintf("https://s3.%s.amazonaws.com/%s", e.cfg.Region, e.cfg.Bucket)
}

// ── AWS Signature V4 ─────────────────────────────────────────────────

func (e *s3Exporter) signRequest(req *http.Request, payload []byte) {
	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzdate := now.Format("20060102T150405Z")

	req.Header.Set("x-amz-date", amzdate)
	req.Header.Set("Host", req.URL.Host)

	// Hash payload
	payloadHash := sha256Hex(payload)
	req.Header.Set("x-amz-content-sha256", payloadHash)

	// Create canonical request
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQueryString := req.URL.RawQuery

	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		req.URL.Host, payloadHash, amzdate)

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method, canonicalURI, canonicalQueryString,
		canonicalHeaders, signedHeaders, payloadHash)

	// Create string to sign
	scope := fmt.Sprintf("%s/%s/s3/aws4_request", datestamp, e.cfg.Region)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzdate, scope, sha256Hex([]byte(canonicalRequest)))

	// Create signing key
	signingKey := getSignatureKey(e.cfg.SecretKey, datestamp, e.cfg.Region, "s3")

	// Create signature
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// Add authorization header
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		e.cfg.AccessKey, scope, signedHeaders, signature))
}

func (e *s3Exporter) signRequestUnsignedPayload(req *http.Request) {
	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzdate := now.Format("20060102T150405Z")

	req.Header.Set("x-amz-date", amzdate)
	req.Header.Set("Host", req.URL.Host)

	payloadHash := "UNSIGNED-PAYLOAD"
	req.Header.Set("x-amz-content-sha256", payloadHash)

	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	signedHeaders := "content-type;host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		req.Header.Get("Content-Type"), req.URL.Host, payloadHash, amzdate)

	canonicalRequest := fmt.Sprintf("%s\n%s\n\n%s\n%s\n%s",
		req.Method, canonicalURI,
		canonicalHeaders, signedHeaders, payloadHash)

	scope := fmt.Sprintf("%s/%s/s3/aws4_request", datestamp, e.cfg.Region)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzdate, scope, sha256Hex([]byte(canonicalRequest)))

	signingKey := getSignatureKey(e.cfg.SecretKey, datestamp, e.cfg.Region, "s3")
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		e.cfg.AccessKey, scope, signedHeaders, signature))
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func getSignatureKey(secret, datestamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(datestamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

// progressReader wraps an io.Reader and reports progress.
type progressReader struct {
	reader     io.Reader
	total      int64
	read       int64
	onProgress ProgressFunc
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.read += int64(n)
	if pr.onProgress != nil && n > 0 {
		pr.onProgress(pr.read, pr.total)
	}
	return n, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
