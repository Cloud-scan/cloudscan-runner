package downloader

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

// Downloader handles downloading source code from presigned URLs
type Downloader struct {
	httpClient *http.Client
	logger     *log.Entry
}

// New creates a new downloader
func New(timeout time.Duration) *Downloader {
	return &Downloader{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: log.WithField("component", "downloader"),
	}
}

// DownloadAndExtract downloads a source archive from a presigned URL and extracts it
func (d *Downloader) DownloadAndExtract(ctx context.Context, presignedURL, destDir string) error {
	d.logger.WithFields(log.Fields{
		"dest_dir": destDir,
	}).Info("Downloading source archive")

	// Create destination directory
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Download to temp file
	tempFile := filepath.Join(os.TempDir(), "source.zip")
	defer os.Remove(tempFile)

	if err := d.downloadFile(ctx, presignedURL, tempFile); err != nil {
		return fmt.Errorf("failed to download source: %w", err)
	}

	d.logger.Info("Download complete, extracting archive")

	// Extract archive
	if err := d.extractZip(tempFile, destDir); err != nil {
		return fmt.Errorf("failed to extract source: %w", err)
	}

	d.logger.Info("Source extracted successfully")
	return nil
}

// downloadFile downloads a file from URL to local path
func (d *Downloader) downloadFile(ctx context.Context, url, filepath string) error {
	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Execute request
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %s", resp.Status)
	}

	// Create output file
	out, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	// Copy data
	written, err := io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	d.logger.WithField("bytes", written).Debug("File downloaded")
	return nil
}

// extractZip extracts a zip archive to destination directory
func (d *Downloader) extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		err := d.extractFile(f, destDir)
		if err != nil {
			return fmt.Errorf("failed to extract %s: %w", f.Name, err)
		}
	}

	return nil
}

// extractFile extracts a single file from zip
func (d *Downloader) extractFile(f *zip.File, destDir string) error {
	// Construct destination path
	destPath := filepath.Join(destDir, f.Name)

	// Check for ZipSlip vulnerability
	if !filepath.HasPrefix(destPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
		return fmt.Errorf("invalid file path: %s", f.Name)
	}

	if f.FileInfo().IsDir() {
		return os.MkdirAll(destPath, f.Mode())
	}

	// Create parent directory
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}

	// Open source file
	srcFile, err := f.Open()
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Create destination file
	destFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer destFile.Close()

	// Copy data
	_, err = io.Copy(destFile, srcFile)
	return err
}