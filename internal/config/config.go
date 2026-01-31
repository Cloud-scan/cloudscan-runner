package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// Config holds all runtime configuration for the scanner runner
type Config struct {
	// Scan metadata
	ScanID             uuid.UUID
	SourceArtifactID   string
	OrganizationID     uuid.UUID
	ProjectID          uuid.UUID
	ScanTypes          []string

	// Repository info
	GitURL    string
	GitBranch string
	GitCommit string

	// Service endpoints
	OrchestratorEndpoint string
	StorageEndpoint      string
	SourceDownloadURL    string  // Presigned URL to download source archive

	// Working directories
	WorkDir    string
	ResultsDir string

	// Timeouts
	ScanTimeout  time.Duration
	DownloadTimeout time.Duration

	// Logging
	LogLevel string
}

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv() (*Config, error) {
	cfg := &Config{}

	// Required fields
	scanIDStr := os.Getenv("SCAN_ID")
	if scanIDStr == "" {
		return nil, fmt.Errorf("SCAN_ID environment variable is required")
	}
	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid SCAN_ID: %w", err)
	}
	cfg.ScanID = scanID

	cfg.SourceArtifactID = os.Getenv("SOURCE_ARTIFACT_ID")
	if cfg.SourceArtifactID == "" {
		return nil, fmt.Errorf("SOURCE_ARTIFACT_ID environment variable is required")
	}

	orgIDStr := os.Getenv("ORGANIZATION_ID")
	if orgIDStr == "" {
		return nil, fmt.Errorf("ORGANIZATION_ID environment variable is required")
	}
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid ORGANIZATION_ID: %w", err)
	}
	cfg.OrganizationID = orgID

	projIDStr := os.Getenv("PROJECT_ID")
	if projIDStr == "" {
		return nil, fmt.Errorf("PROJECT_ID environment variable is required")
	}
	projID, err := uuid.Parse(projIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid PROJECT_ID: %w", err)
	}
	cfg.ProjectID = projID

	cfg.OrchestratorEndpoint = os.Getenv("ORCHESTRATOR_ENDPOINT")
	if cfg.OrchestratorEndpoint == "" {
		return nil, fmt.Errorf("ORCHESTRATOR_ENDPOINT environment variable is required")
	}

	cfg.SourceDownloadURL = os.Getenv("SOURCE_DOWNLOAD_URL")
	if cfg.SourceDownloadURL == "" {
		return nil, fmt.Errorf("SOURCE_DOWNLOAD_URL environment variable is required")
	}

	scanTypesStr := os.Getenv("SCAN_TYPES")
	if scanTypesStr == "" {
		return nil, fmt.Errorf("SCAN_TYPES environment variable is required")
	}
	cfg.ScanTypes = strings.Split(scanTypesStr, ",")

	// Optional fields with defaults
	cfg.GitURL = getEnv("GIT_URL", "")
	cfg.GitBranch = getEnv("GIT_BRANCH", "")
	cfg.GitCommit = getEnv("GIT_COMMIT", "")
	cfg.StorageEndpoint = getEnv("STORAGE_ENDPOINT", "")

	cfg.WorkDir = getEnv("WORK_DIR", "/workspace")
	cfg.ResultsDir = getEnv("RESULTS_DIR", "/results")
	cfg.LogLevel = getEnv("LOG_LEVEL", "info")

	// Parse timeout values
	scanTimeoutSec, err := strconv.Atoi(getEnv("SCAN_TIMEOUT", "1800"))
	if err != nil {
		log.Warnf("Invalid SCAN_TIMEOUT, using default: %v", err)
		scanTimeoutSec = 1800
	}
	cfg.ScanTimeout = time.Duration(scanTimeoutSec) * time.Second

	downloadTimeoutSec, err := strconv.Atoi(getEnv("DOWNLOAD_TIMEOUT", "300"))
	if err != nil {
		log.Warnf("Invalid DOWNLOAD_TIMEOUT, using default: %v", err)
		downloadTimeoutSec = 300
	}
	cfg.DownloadTimeout = time.Duration(downloadTimeoutSec) * time.Second

	log.WithFields(log.Fields{
		"scan_id":       cfg.ScanID,
		"artifact_id":   cfg.SourceArtifactID,
		"scan_types":    cfg.ScanTypes,
		"orchestrator":  cfg.OrchestratorEndpoint,
		"work_dir":      cfg.WorkDir,
		"scan_timeout":  cfg.ScanTimeout,
	}).Info("Configuration loaded from environment")

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}