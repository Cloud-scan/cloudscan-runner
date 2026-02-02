package scanners

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	pb "github.com/cloud-scan/cloudscan-orchestrator/generated/proto"
	log "github.com/sirupsen/logrus"
)

// TruffleHogScanner implements secrets detection using TruffleHog
type TruffleHogScanner struct {
	logger *log.Entry
}

// NewTruffleHogScanner creates a new TruffleHog scanner
func NewTruffleHogScanner() *TruffleHogScanner {
	return &TruffleHogScanner{
		logger: log.WithField("scanner", "trufflehog"),
	}
}

// Name returns the scanner name
func (t *TruffleHogScanner) Name() string {
	return "trufflehog"
}

// ScanType returns the scan type
func (t *TruffleHogScanner) ScanType() pb.ScanType {
	return pb.ScanType_SECRETS
}

// IsAvailable checks if trufflehog is installed
func (t *TruffleHogScanner) IsAvailable() bool {
	_, err := exec.LookPath("trufflehog")
	return err == nil
}

// Scan executes TruffleHog scan
func (t *TruffleHogScanner) Scan(ctx context.Context, sourceDir string) ([]*pb.Finding, error) {
	t.logger.WithField("source_dir", sourceDir).Info("Starting TruffleHog scan")

	if !t.IsAvailable() {
		return nil, fmt.Errorf("trufflehog is not installed")
	}

	// Create results file
	resultsFile := filepath.Join(os.TempDir(), "trufflehog-results.json")
	defer os.Remove(resultsFile)

	// Run trufflehog
	cmd := exec.CommandContext(ctx, "trufflehog",
		"filesystem",                  // Filesystem scan
		"--json",                      // JSON output
		"--no-verification",           // Don't verify secrets (faster)
		"--no-update",                 // Disable auto-update (prevents exit code 1 in containers)
		sourceDir,                     // Source directory
	)

	// Capture output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start trufflehog: %w", err)
	}

	// Parse streaming JSON output
	var findings []*pb.Finding
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result struct {
			SourceMetadata struct {
				Data struct {
					Filesystem struct {
						File string `json:"file"`
						Line int    `json:"line"`
					} `json:"Filesystem"`
				} `json:"Data"`
			} `json:"SourceMetadata"`
			SourceName  string `json:"SourceName"`
			DetectorName string `json:"DetectorName"`
			Raw         string `json:"Raw"`
			Verified    bool   `json:"Verified"`
		}

		if err := json.Unmarshal([]byte(line), &result); err != nil {
			t.logger.WithError(err).Warn("Failed to parse trufflehog output line")
			continue
		}

		title := fmt.Sprintf("Secret detected: %s", result.DetectorName)
		description := fmt.Sprintf("Potential secret found in source code")
		if result.Verified {
			description += " (VERIFIED - this secret is active!)"
		}

		finding := &pb.Finding{
			ScanType:    pb.ScanType_SECRETS,
			Severity:    pb.Severity_HIGH, // Secrets are always high severity
			Title:       title,
			Description: description,
			FilePath:    result.SourceMetadata.Data.Filesystem.File,
			LineNumber:  int32(result.SourceMetadata.Data.Filesystem.Line),
		}

		findings = append(findings, finding)
	}

	if err := scanner.Err(); err != nil {
		t.logger.WithError(err).Warn("Error reading trufflehog output")
	}

	if err := cmd.Wait(); err != nil {
		t.logger.WithError(err).Warn("TruffleHog exited with error (may have findings)")
	}

	t.logger.WithField("findings", len(findings)).Info("TruffleHog scan complete")
	return findings, nil
}
