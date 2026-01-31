package orchestrator

import (
	"context"
	"fmt"
	"time"

	pb "github.com/cloud-scan/cloudscan-orchestrator/generated/proto"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client wraps the orchestrator gRPC client
type Client struct {
	conn   *grpc.ClientConn
	client pb.ScanServiceClient
	logger *log.Entry
}

// NewClient creates a new orchestrator client
func NewClient(endpoint string) (*Client, error) {
	logger := log.WithField("component", "orchestrator-client")
	logger.WithField("endpoint", endpoint).Info("Connecting to orchestrator")

	// Configure gRPC dial options
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	}

	// Connect with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to orchestrator: %w", err)
	}

	client := pb.NewScanServiceClient(conn)
	logger.Info("Successfully connected to orchestrator")

	return &Client{
		conn:   conn,
		client: client,
		logger: logger,
	}, nil
}

// UpdateScanStatus updates the scan status in orchestrator
func (c *Client) UpdateScanStatus(ctx context.Context, scanID uuid.UUID, status pb.ScanStatus, errorMsg string) error {
	c.logger.WithFields(log.Fields{
		"scan_id": scanID,
		"status":  status,
	}).Debug("Updating scan status")

	req := &pb.UpdateScanRequest{
		Id:     scanID.String(),
		Status: status,
	}

	if errorMsg != "" {
		req.ErrorMessage = errorMsg
	}

	_, err := c.client.UpdateScan(ctx, req)
	if err != nil {
		c.logger.WithError(err).Error("Failed to update scan status")
		return fmt.Errorf("failed to update scan status: %w", err)
	}

	c.logger.Info("Scan status updated successfully")
	return nil
}

// CreateFindings sends findings to orchestrator in batch
func (c *Client) CreateFindings(ctx context.Context, scanID uuid.UUID, findings []*pb.Finding) error {
	c.logger.WithFields(log.Fields{
		"scan_id": scanID,
		"count":   len(findings),
	}).Info("Creating findings")

	if len(findings) == 0 {
		c.logger.Info("No findings to create")
		return nil
	}

	req := &pb.CreateFindingsRequest{
		ScanId:   scanID.String(),
		Findings: findings,
	}

	resp, err := c.client.CreateFindings(ctx, req)
	if err != nil {
		c.logger.WithError(err).Error("Failed to create findings")
		return fmt.Errorf("failed to create findings: %w", err)
	}

	c.logger.WithField("created_count", resp.CreatedCount).Info("Findings created successfully")
	return nil
}

// UpdateFindingsCount updates the total findings count for a scan
func (c *Client) UpdateFindingsCount(ctx context.Context, scanID uuid.UUID, count int32) error {
	c.logger.WithFields(log.Fields{
		"scan_id": scanID,
		"count":   count,
	}).Debug("Updating findings count")

	req := &pb.UpdateScanRequest{
		Id:            scanID.String(),
		TotalFindings: count,
	}

	_, err := c.client.UpdateScan(ctx, req)
	if err != nil {
		c.logger.WithError(err).Error("Failed to update findings count")
		return fmt.Errorf("failed to update findings count: %w", err)
	}

	return nil
}

// Close closes the gRPC connection
func (c *Client) Close() error {
	c.logger.Info("Closing orchestrator connection")
	return c.conn.Close()
}