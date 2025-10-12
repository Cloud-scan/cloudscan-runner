package main

import (
	//"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	// Get configuration from environment
	workDir := getEnv("WORK_DIR", "/app/scans")
	resultsDir := getEnv("RESULTS_DIR", "/app/results")
	scanTimeout := getEnv("SCAN_TIMEOUT", "1800")

	log.WithFields(log.Fields{
		"workDir":     workDir,
		"resultsDir":  resultsDir,
		"scanTimeout": scanTimeout,
	}).Info("Runner configuration loaded")

	// Verify scanner tools are available
	checkScannerTools()

	// TODO: Implement actual runner logic
	// - Listen for scan jobs from orchestrator
	// - Execute scanner tools (Trivy, Semgrep, TruffleHog, ScanCode)
	// - Upload results to storage service

	// For now, just run indefinitely
	log.Info("Runner is ready and waiting for scan jobs...")

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Info("Shutting down runner...")
	time.Sleep(2 * time.Second) // Allow ongoing scans to complete
	log.Info("Runner stopped")
}

func checkScannerTools() {
	tools := []string{"trivy", "semgrep", "trufflehog", "scancode"}

	log.Info("Checking for scanner tools...")
	for _, tool := range tools {
		if _, err := os.Stat("/usr/local/bin/" + tool); err == nil {
			log.Infof("✓ %s found", tool)
		} else if _, err := os.Stat("/usr/bin/" + tool); err == nil {
			log.Infof("✓ %s found", tool)
		} else {
			log.Warnf("✗ %s not found - some scans may not be available", tool)
		}
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func init() {
	// Set up logging
	logLevel := getEnv("LOG_LEVEL", "info")
	switch logLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	log.Infof("Log level set to: %s", logLevel)
}
