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

// ScanCodeScanner implements license compliance scanning using ScanCode
type ScanCodeScanner struct {
	logger *log.Entry
}

// NewScanCodeScanner creates a new ScanCode scanner
func NewScanCodeScanner() *ScanCodeScanner {
	return &ScanCodeScanner{
		logger: log.WithField("scanner", "scancode"),
	}
}

// Name returns the scanner name
func (s *ScanCodeScanner) Name() string {
	return "scancode"
}

// ScanType returns the scan type
func (s *ScanCodeScanner) ScanType() pb.ScanType {
	return pb.ScanType_LICENSE
}

// IsAvailable checks if scancode is installed
func (s *ScanCodeScanner) IsAvailable() bool {
	_, err := exec.LookPath("scancode")
	return err == nil
}

// Scan executes ScanCode scan
func (s *ScanCodeScanner) Scan(ctx context.Context, sourceDir string) ([]*pb.Finding, error) {
	s.logger.WithField("source_dir", sourceDir).Info("Starting ScanCode scan")

	if !s.IsAvailable() {
		return nil, fmt.Errorf("scancode is not installed")
	}

	// Create results file
	resultsFile := filepath.Join(os.TempDir(), "scancode-results.json")
	defer os.Remove(resultsFile)

	// Run scancode
	cmd := exec.CommandContext(ctx, "scancode",
		"--license",                   // Scan for licenses
		"--copyright",                 // Scan for copyrights
		"--json-pp", resultsFile,      // JSON output
		"--processes", "4",            // Parallel processing
		sourceDir,                     // Source directory
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.WithError(err).Warn("ScanCode exited with error (may have findings)")
	}

	s.logger.WithField("output_len", len(output)).Debug("ScanCode scan complete")

	// Parse results
	findings, err := s.parseResults(resultsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse scancode results: %w", err)
	}

	s.logger.WithField("findings", len(findings)).Info("ScanCode scan complete")
	return findings, nil
}

// parseResults parses ScanCode JSON output
func (s *ScanCodeScanner) parseResults(resultsFile string) ([]*pb.Finding, error) {
	data, err := os.ReadFile(resultsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read results: %w", err)
	}

	var result struct {
		Files []struct {
			Path     string `json:"path"`
			Licenses []struct {
				Key       string  `json:"key"`
				ShortName string  `json:"short_name"`
				Name      string  `json:"name"`
				Category  string  `json:"category"`
				Score     float64 `json:"score"`
			} `json:"licenses"`
			Copyrights []struct {
				Value string `json:"value"`
			} `json:"copyrights"`
		} `json:"files"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	findings := make([]*pb.Finding, 0)
	for _, file := range result.Files {
		// Report license findings
		for _, license := range file.Licenses {
			severity := s.getLicenseSeverity(license.Category)

			title := fmt.Sprintf("License: %s", license.ShortName)
			description := fmt.Sprintf("License '%s' detected in file", license.Name)
			if license.Category != "" {
				description += fmt.Sprintf(" (Category: %s)", license.Category)
			}

			finding := &pb.Finding{
				ScanType:    pb.ScanType_LICENSE,
				Severity:    severity,
				Title:       title,
				Description: description,
				FilePath:    file.Path,
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// getLicenseSeverity determines severity based on license category
func (s *ScanCodeScanner) getLicenseSeverity(category string) pb.Severity {
	switch category {
	case "Copyleft", "Strong Copyleft":
		return pb.Severity_HIGH // GPL-like licenses
	case "Copyleft Limited":
		return pb.Severity_MEDIUM // LGPL-like licenses
	case "Permissive":
		return pb.Severity_LOW // MIT, Apache, BSD
	case "Proprietary Free":
		return pb.Severity_LOW
	default:
		return pb.Severity_MEDIUM // Unknown licenses
	}
}