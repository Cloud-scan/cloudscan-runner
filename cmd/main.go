package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cloud-scan/cloudscan-runner/internal/config"
	"github.com/cloud-scan/cloudscan-runner/internal/downloader"
	"github.com/cloud-scan/cloudscan-runner/internal/orchestrator"
	"github.com/cloud-scan/cloudscan-runner/internal/scanners"
	pb "github.com/cloud-scan/cloudscan-orchestrator/generated/proto"
	log "github.com/sirupsen/logrus"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.InfoLevel)

	log.WithFields(log.Fields{
		"version":   version,
		"commit":    commit,
		"buildDate": buildDate,
	}).Info("Starting CloudScan Runner")

	// Load configuration from environment
	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.WithError(err).Fatal("Failed to load configuration")
	}

	// Set log level
	setLogLevel(cfg.LogLevel)

	// Run scanner job
	if err := runScan(cfg); err != nil {
		log.WithError(err).Fatal("Scan failed")
		os.Exit(1)
	}

	log.Info("Scan completed successfully")
}

func runScan(cfg *config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ScanTimeout)
	defer cancel()

	// Connect to orchestrator
	log.Info("Connecting to orchestrator")
	orchClient, err := orchestrator.NewClient(cfg.OrchestratorEndpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to orchestrator: %w", err)
	}
	defer orchClient.Close()

	// Update scan status to RUNNING
	if err := orchClient.UpdateScanStatus(ctx, cfg.ScanID, pb.ScanStatus_RUNNING, ""); err != nil {
		log.WithError(err).Warn("Failed to update scan status to RUNNING")
	}

	// Prepare source code (either download artifact or clone from Git)
	dl := downloader.New(cfg.DownloadTimeout)

	if cfg.SourceDownloadURL != "" {
		// Artifact flow: Download from presigned URL
		log.Info("Downloading source code from artifact")
		if err := dl.DownloadAndExtract(ctx, cfg.SourceDownloadURL, cfg.WorkDir); err != nil {
			orchClient.UpdateScanStatus(ctx, cfg.ScanID, pb.ScanStatus_FAILED, fmt.Sprintf("Failed to download source: %v", err))
			return fmt.Errorf("failed to download source: %w", err)
		}
	} else if cfg.GitURL != "" {
		// Git flow: Clone repository
		log.WithFields(log.Fields{
			"repo_url": cfg.GitURL,
			"branch":   cfg.GitBranch,
			"commit":   cfg.GitCommit,
		}).Info("Cloning source code from Git repository")

		if err := dl.CloneGit(ctx, cfg.GitURL, cfg.GitBranch, cfg.GitCommit, cfg.WorkDir); err != nil {
			orchClient.UpdateScanStatus(ctx, cfg.ScanID, pb.ScanStatus_FAILED, fmt.Sprintf("Failed to clone repository: %v", err))
			return fmt.Errorf("failed to clone repository: %w", err)
		}
	} else {
		// This should never happen due to config validation, but handle it anyway
		errMsg := "No source specified: neither SOURCE_DOWNLOAD_URL nor REPOSITORY_URL provided"
		orchClient.UpdateScanStatus(ctx, cfg.ScanID, pb.ScanStatus_FAILED, errMsg)
		return fmt.Errorf(errMsg)
	}

	// Initialize scanners based on requested scan types
	scannerList := initializeScanners(cfg.ScanTypes)
	if len(scannerList) == 0 {
		orchClient.UpdateScanStatus(ctx, cfg.ScanID, pb.ScanStatus_FAILED, "No scanners available for requested scan types")
		return fmt.Errorf("no scanners available")
	}

	log.WithField("scanner_count", len(scannerList)).Info("Initialized scanners")

	// Run scanners in parallel
	log.Info("Starting parallel scan execution")
	results := runScannersParallel(ctx, scannerList, cfg.WorkDir)

	// Collect all findings
	var allFindings []*pb.Finding
	var scanErrors []string

	for _, result := range results {
		if result.Error != nil {
			log.WithError(result.Error).WithField("scanner", result.ScannerName).Error("Scanner failed")
			scanErrors = append(scanErrors, fmt.Sprintf("%s: %v", result.ScannerName, result.Error))
			continue
		}

		log.WithFields(log.Fields{
			"scanner":  result.ScannerName,
			"findings": len(result.Findings),
		}).Info("Scanner completed")

		allFindings = append(allFindings, result.Findings...)
	}

	// Upload findings to orchestrator
	if len(allFindings) > 0 {
		log.WithField("total_findings", len(allFindings)).Info("Uploading findings to orchestrator")
		if err := orchClient.CreateFindings(ctx, cfg.ScanID, allFindings); err != nil {
			log.WithError(err).Error("Failed to upload findings")
			scanErrors = append(scanErrors, fmt.Sprintf("Failed to upload findings: %v", err))
		}

		// Update findings count
		if err := orchClient.UpdateFindingsCount(ctx, cfg.ScanID, int32(len(allFindings))); err != nil {
			log.WithError(err).Warn("Failed to update findings count")
		}
	}

	// Update final scan status
	if len(scanErrors) > 0 {
		errorMsg := fmt.Sprintf("Scan completed with errors: %v", scanErrors)
		orchClient.UpdateScanStatus(ctx, cfg.ScanID, pb.ScanStatus_FAILED, errorMsg)
		return fmt.Errorf("scan had errors: %v", scanErrors)
	}

	if err := orchClient.UpdateScanStatus(ctx, cfg.ScanID, pb.ScanStatus_COMPLETED, ""); err != nil {
		log.WithError(err).Warn("Failed to update scan status to COMPLETED")
	}

	return nil
}

// initializeScanners creates scanner instances based on requested scan types
func initializeScanners(scanTypes []string) []scanners.Scanner {
	var scannerList []scanners.Scanner

	for _, scanType := range scanTypes {
		switch scanType {
		case "sast", "SAST":
			scanner := scanners.NewSemgrepScanner()
			if scanner.IsAvailable() {
				scannerList = append(scannerList, scanner)
			} else {
				log.Warn("Semgrep scanner not available")
			}

		case "sca", "SCA":
			scanner := scanners.NewTrivyScanner()
			if scanner.IsAvailable() {
				scannerList = append(scannerList, scanner)
			} else {
				log.Warn("Trivy scanner not available")
			}

		case "secrets", "SECRETS":
			scanner := scanners.NewTruffleHogScanner()
			if scanner.IsAvailable() {
				scannerList = append(scannerList, scanner)
			} else {
				log.Warn("TruffleHog scanner not available")
			}

		case "license", "LICENSE":
			scanner := scanners.NewScanCodeScanner()
			if scanner.IsAvailable() {
				scannerList = append(scannerList, scanner)
			} else {
				log.Warn("ScanCode scanner not available")
			}

		default:
			log.WithField("scan_type", scanType).Warn("Unknown scan type")
		}
	}

	return scannerList
}

// runScannersParallel executes all scanners in parallel using goroutines
func runScannersParallel(ctx context.Context, scannerList []scanners.Scanner, sourceDir string) []*scanners.Result {
	var wg sync.WaitGroup
	results := make([]*scanners.Result, len(scannerList))

	for i, scanner := range scannerList {
		wg.Add(1)
		go func(idx int, scnr scanners.Scanner) {
			defer wg.Done()

			startTime := time.Now()
			log.WithField("scanner", scnr.Name()).Info("Starting scanner")

			findings, err := scnr.Scan(ctx, sourceDir)
			duration := time.Since(startTime)

			results[idx] = &scanners.Result{
				Findings:    findings,
				ScanType:    scnr.ScanType(),
				ScannerName: scnr.Name(),
				Error:       err,
			}

			if err != nil {
				log.WithFields(log.Fields{
					"scanner":  scnr.Name(),
					"duration": duration,
				}).WithError(err).Error("Scanner failed")
			} else {
				log.WithFields(log.Fields{
					"scanner":  scnr.Name(),
					"findings": len(findings),
					"duration": duration,
				}).Info("Scanner completed")
			}
		}(i, scanner)
	}

	wg.Wait()
	return results
}

func setLogLevel(level string) {
	switch level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
	log.Infof("Log level set to: %s", level)
}