package export

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ftpExporter uploads files via FTP (with optional explicit TLS).
type ftpExporter struct {
	cfg *FTPConfig
}

// NewFTPExporter creates a new FTP exporter.
func NewFTPExporter(cfg *FTPConfig) (Exporter, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("FTP host is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 21
	}
	if cfg.Username == "" {
		cfg.Username = "anonymous"
	}
	if cfg.RemotePath == "" {
		cfg.RemotePath = "/"
	}
	return &ftpExporter{cfg: cfg}, nil
}

func (e *ftpExporter) TestConnection() error {
	fc, err := e.connect()
	if err != nil {
		return err
	}
	defer fc.close()

	if err := fc.login(e.cfg.Username, e.cfg.Password); err != nil {
		return err
	}
	return nil
}

func (e *ftpExporter) Upload(filePath string, onProgress ProgressFunc) (*Result, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", filePath, err)
	}

	fc, err := e.connect()
	if err != nil {
		return nil, err
	}
	defer fc.close()

	if err := fc.login(e.cfg.Username, e.cfg.Password); err != nil {
		return nil, err
	}

	// Set binary transfer mode
	if err := fc.command("TYPE I", 200); err != nil {
		return nil, fmt.Errorf("setting binary mode: %w", err)
	}

	// Change to remote directory
	if e.cfg.RemotePath != "" && e.cfg.RemotePath != "/" {
		if err := fc.command("CWD "+e.cfg.RemotePath, 250); err != nil {
			return nil, fmt.Errorf("changing directory to %s: %w", e.cfg.RemotePath, err)
		}
	}

	// Enter passive mode
	dataConn, err := fc.passive()
	if err != nil {
		return nil, fmt.Errorf("entering passive mode: %w", err)
	}
	defer dataConn.Close()

	// Initiate store
	fileName := filepath.Base(filePath)
	if err := fc.command("STOR "+fileName, 150); err != nil {
		return nil, fmt.Errorf("STOR command: %w", err)
	}

	// Upload file
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", filePath, err)
	}
	defer f.Close()

	var bytesSent int64
	buf := make([]byte, 64*1024)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			written, writeErr := dataConn.Write(buf[:n])
			bytesSent += int64(written)
			if onProgress != nil {
				onProgress(bytesSent, info.Size())
			}
			if writeErr != nil {
				return nil, fmt.Errorf("writing to FTP: %w", writeErr)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("reading file: %w", readErr)
		}
	}

	dataConn.Close()

	// Read transfer complete response
	if _, err := fc.readResponse(226); err != nil {
		return nil, fmt.Errorf("transfer completion: %w", err)
	}

	return &Result{
		Success:   true,
		Message:   fmt.Sprintf("Uploaded %s to %s:%d/%s", fileName, e.cfg.Host, e.cfg.Port, e.cfg.RemotePath),
		BytesSent: bytesSent,
	}, nil
}

func (e *ftpExporter) connect() (*ftpConn, error) {
	addr := fmt.Sprintf("%s:%d", e.cfg.Host, e.cfg.Port)
	conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("FTP connect to %s: %w", addr, err)
	}

	fc := &ftpConn{conn: conn, reader: bufio.NewReader(conn)}

	// Read welcome banner
	if _, err := fc.readResponse(220); err != nil {
		conn.Close()
		return nil, fmt.Errorf("FTP welcome: %w", err)
	}

	// Upgrade to TLS if requested
	if e.cfg.UseTLS {
		if err := fc.sendCmd("AUTH TLS"); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := fc.readResponse(234); err != nil {
			conn.Close()
			return nil, fmt.Errorf("AUTH TLS: %w", err)
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         e.cfg.Host,
			InsecureSkipVerify: true, // forensic tools often connect to internal servers
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		fc.conn = tlsConn
		fc.reader = bufio.NewReader(tlsConn)

		// Protect data channel
		if err := fc.command("PBSZ 0", 200); err != nil {
			fc.close()
			return nil, err
		}
		if err := fc.command("PROT P", 200); err != nil {
			fc.close()
			return nil, err
		}
	}

	return fc, nil
}

// --- FTP protocol implementation ---

type ftpConn struct {
	conn   net.Conn
	reader *bufio.Reader
}

func (fc *ftpConn) close() {
	fc.sendCmd("QUIT")
	fc.conn.Close()
}

func (fc *ftpConn) login(user, pass string) error {
	if err := fc.command("USER "+user, 331); err != nil {
		return fmt.Errorf("FTP USER: %w", err)
	}
	if err := fc.command("PASS "+pass, 230); err != nil {
		return fmt.Errorf("FTP PASS: authentication failed")
	}
	return nil
}

func (fc *ftpConn) command(cmd string, expectedCode int) error {
	if err := fc.sendCmd(cmd); err != nil {
		return err
	}
	_, err := fc.readResponse(expectedCode)
	return err
}

func (fc *ftpConn) sendCmd(cmd string) error {
	fc.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := fmt.Fprintf(fc.conn, "%s\r\n", cmd)
	return err
}

func (fc *ftpConn) readResponse(expected int) (string, error) {
	fc.conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	var fullResponse strings.Builder
	for {
		line, err := fc.reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("reading FTP response: %w", err)
		}
		fullResponse.WriteString(line)

		// Multi-line responses: "123-text" continues, "123 text" ends
		if len(line) >= 4 && line[3] == ' ' {
			code, parseErr := strconv.Atoi(line[:3])
			if parseErr != nil {
				return fullResponse.String(), fmt.Errorf("invalid FTP response: %s", line)
			}
			if code != expected {
				return fullResponse.String(), fmt.Errorf("FTP error: expected %d, got %s", expected, strings.TrimSpace(fullResponse.String()))
			}
			return fullResponse.String(), nil
		}
	}
}

// passive enters PASV mode and returns a data connection.
func (fc *ftpConn) passive() (net.Conn, error) {
	if err := fc.sendCmd("PASV"); err != nil {
		return nil, err
	}
	resp, err := fc.readResponse(227)
	if err != nil {
		return nil, err
	}

	// Parse: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
	start := strings.Index(resp, "(")
	end := strings.Index(resp, ")")
	if start < 0 || end < 0 || end <= start {
		return nil, fmt.Errorf("cannot parse PASV response: %s", resp)
	}

	parts := strings.Split(resp[start+1:end], ",")
	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid PASV response: %s", resp)
	}

	p1, _ := strconv.Atoi(strings.TrimSpace(parts[4]))
	p2, _ := strconv.Atoi(strings.TrimSpace(parts[5]))
	port := p1*256 + p2
	host := strings.Join(parts[:4], ".")

	addr := fmt.Sprintf("%s:%d", host, port)
	dataConn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("data connection to %s: %w", addr, err)
	}

	return dataConn, nil
}
