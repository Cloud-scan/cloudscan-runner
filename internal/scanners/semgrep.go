package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	pb "github.com/cloud-scan/cloudscan-orchestrator/generated/proto"
	log "github.com/sirupsen/logrus"
)

// SemgrepScanner implements SAST scanning using Semgrep
type SemgrepScanner struct {
	logger *log.Entry
}

// NewSemgrepScanner creates a new Semgrep scanner
func NewSemgrepScanner() *SemgrepScanner {
	return &SemgrepScanner{
		logger: log.WithField("scanner", "semgrep"),
	}
}

// Name returns the scanner name
func (s *SemgrepScanner) Name() string {
	return "semgrep"
}

// ScanType returns the scan type
func (s *SemgrepScanner) ScanType() pb.ScanType {
	return pb.ScanType_SAST
}

// IsAvailable checks if semgrep is installed
func (s *SemgrepScanner) IsAvailable() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}

// Scan executes Semgrep scan
func (s *SemgrepScanner) Scan(ctx context.Context, sourceDir string) ([]*pb.Finding, error) {
	s.logger.WithField("source_dir", sourceDir).Info("Starting Semgrep scan")

	if !s.IsAvailable() {
		return nil, fmt.Errorf("semgrep is not installed")
	}

	// Create results file
	resultsFile := filepath.Join(os.TempDir(), "semgrep-results.json")
	defer os.Remove(resultsFile)

	// Run semgrep
	cmd := exec.CommandContext(ctx, "semgrep",
		"--config=auto",              // Use automatic ruleset
		"--json",                      // JSON output
		"--output="+resultsFile,       // Output file
		"--timeout=0",                 // No timeout per file
		"--max-memory=0",              // No memory limit
		sourceDir,                     // Source directory
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Semgrep returns non-zero if findings are found
		s.logger.WithError(err).Warn("Semgrep exited with error (may have findings)")
	}

	s.logger.WithField("output_len", len(output)).Debug("Semgrep scan complete")

	// Parse results
	findings, err := s.parseResults(resultsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse semgrep results: %w", err)
	}

	s.logger.WithField("findings", len(findings)).Info("Semgrep scan complete")
	return findings, nil
}

// parseResults parses Semgrep JSON output
func (s *SemgrepScanner) parseResults(resultsFile string) ([]*pb.Finding, error) {
	data, err := os.ReadFile(resultsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read results: %w", err)
	}

	var result struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
				Col  int `json:"col"`
			} `json:"start"`
			End struct {
				Line int `json:"line"`
				Col  int `json:"col"`
			} `json:"end"`
			Extra struct {
				Message  string `json:"message"`
				Metadata struct {
					Severity    string   `json:"severity"`
					CWE         []string `json:"cwe"`
					Confidence  string   `json:"confidence"`
					References  []string `json:"references"`
				} `json:"metadata"`
				Lines string `json:"lines"`
			} `json:"extra"`
		} `json:"results"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	findings := make([]*pb.Finding, 0, len(result.Results))
	for _, r := range result.Results {
		severity := s.mapSeverity(r.Extra.Metadata.Severity)

		finding := &pb.Finding{
			ScanType:    pb.ScanType_SAST,
			Severity:    severity,
			Title:       r.CheckID,
			Description: r.Extra.Message,
			FilePath:    r.Path,
			LineNumber:  int32(r.Start.Line),
			CodeSnippet: r.Extra.Lines,
		}

		// Add CWE if available
		if len(r.Extra.Metadata.CWE) > 0 {
			finding.CweId = r.Extra.Metadata.CWE[0]
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// mapSeverity maps Semgrep severity to proto severity
func (s *SemgrepScanner) mapSeverity(severity string) pb.Severity {
	switch severity {
	case "ERROR":
		return pb.Severity_HIGH
	case "WARNING":
		return pb.Severity_MEDIUM
	case "INFO":
		return pb.Severity_LOW
	default:
		return pb.Severity_MEDIUM
	}
}