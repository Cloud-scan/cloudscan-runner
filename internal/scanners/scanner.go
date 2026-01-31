package scanners

import (
	"context"

	pb "github.com/cloud-scan/cloudscan-orchestrator/generated/proto"
)

// Scanner defines the interface for all security scanners
type Scanner interface {
	// Name returns the scanner name
	Name() string

	// ScanType returns the type of scan this scanner performs
	ScanType() pb.ScanType

	// Scan executes the scanner and returns findings
	Scan(ctx context.Context, sourceDir string) ([]*pb.Finding, error)

	// IsAvailable checks if the scanner tool is installed
	IsAvailable() bool
}

// Result represents the combined scan results
type Result struct {
	Findings     []*pb.Finding
	ScanType     pb.ScanType
	ScannerName  string
	Error        error
}