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

// TrivyScanner implements SCA scanning using Trivy
type TrivyScanner struct {
	logger *log.Entry
}

// NewTrivyScanner creates a new Trivy scanner
func NewTrivyScanner() *TrivyScanner {
	return &TrivyScanner{
		logger: log.WithField("scanner", "trivy"),
	}
}

// Name returns the scanner name
func (t *TrivyScanner) Name() string {
	return "trivy"
}

// ScanType returns the scan type
func (t *TrivyScanner) ScanType() pb.ScanType {
	return pb.ScanType_SCA
}

// IsAvailable checks if trivy is installed
func (t *TrivyScanner) IsAvailable() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
}

// Scan executes Trivy scan
func (t *TrivyScanner) Scan(ctx context.Context, sourceDir string) ([]*pb.Finding, error) {
	t.logger.WithField("source_dir", sourceDir).Info("Starting Trivy scan")

	if !t.IsAvailable() {
		return nil, fmt.Errorf("trivy is not installed")
	}

	// Create results file
	resultsFile := filepath.Join(os.TempDir(), "trivy-results.json")
	defer os.Remove(resultsFile)

	// Run trivy
	cmd := exec.CommandContext(ctx, "trivy",
		"fs",                           // Filesystem scan
		"--format=json",                // JSON output
		"--output="+resultsFile,        // Output file
		"--scanners=vuln",              // Scan for vulnerabilities
		"--severity=CRITICAL,HIGH,MEDIUM,LOW", // All severities
		sourceDir,                      // Source directory
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.logger.WithError(err).Warn("Trivy exited with error (may have findings)")
	}

	t.logger.WithField("output_len", len(output)).Debug("Trivy scan complete")

	// Parse results
	findings, err := t.parseResults(resultsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trivy results: %w", err)
	}

	t.logger.WithField("findings", len(findings)).Info("Trivy scan complete")
	return findings, nil
}

// parseResults parses Trivy JSON output
func (t *TrivyScanner) parseResults(resultsFile string) ([]*pb.Finding, error) {
	data, err := os.ReadFile(resultsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read results: %w", err)
	}

	var result struct {
		Results []struct {
			Target         string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID  string  `json:"VulnerabilityID"`
				PkgName          string  `json:"PkgName"`
				InstalledVersion string  `json:"InstalledVersion"`
				FixedVersion     string  `json:"FixedVersion"`
				Severity         string  `json:"Severity"`
				Title            string  `json:"Title"`
				Description      string  `json:"Description"`
				References       []string `json:"References"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	findings := make([]*pb.Finding, 0)
	for _, r := range result.Results {
		for _, v := range r.Vulnerabilities {
			severity := t.mapSeverity(v.Severity)

			title := fmt.Sprintf("%s in %s@%s", v.VulnerabilityID, v.PkgName, v.InstalledVersion)
			description := v.Description
			if v.FixedVersion != "" {
				description += fmt.Sprintf("\n\nFixed in version: %s", v.FixedVersion)
			}

			finding := &pb.Finding{
				ScanType:    pb.ScanType_SCA,
				Severity:    severity,
				Title:       title,
				Description: description,
				FilePath:    r.Target,
				CveId:       v.VulnerabilityID,
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// mapSeverity maps Trivy severity to proto severity
func (t *TrivyScanner) mapSeverity(severity string) pb.Severity {
	switch severity {
	case "CRITICAL":
		return pb.Severity_CRITICAL
	case "HIGH":
		return pb.Severity_HIGH
	case "MEDIUM":
		return pb.Severity_MEDIUM
	case "LOW":
		return pb.Severity_LOW
	default:
		return pb.Severity_MEDIUM
	}
}