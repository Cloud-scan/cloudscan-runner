# CloudScan Runner

> Scanner executor for CloudScan - runs security scans inside Kubernetes Jobs

## Overview

CloudScan Runner is a containerized scanner executor that runs as a Kubernetes Job. It downloads source code, executes multiple security scanners in parallel, and reports findings back to the orchestrator.

## Scanners Included

| Type | Tool | Purpose |
|------|------|---------|
| **SAST** | Semgrep | Static application security testing |
| **SCA** | Trivy | Software composition analysis (dependencies) |
| **Secrets** | TruffleHog | Detect leaked credentials and API keys |
| **License** | ScanCode Toolkit | License compliance checking |

## Architecture Flow

```
1. K8s Job spawned by Orchestrator
   ├─ Environment variables contain:
   │  ├─ SCAN_ID
   │  ├─ SOURCE_DOWNLOAD_URL (presigned S3 URL)
   │  ├─ ORCHESTRATOR_ENDPOINT
   │  └─ SCAN_TYPES
   │
2. Runner starts
   ├─ Downloads source from S3 using presigned URL
   ├─ Extracts to /workspace
   │
3. Executes scanners in parallel
   ├─ Semgrep (SAST)
   ├─ Trivy (SCA)
   ├─ TruffleHog (Secrets)
   └─ ScanCode (License)
   │
4. Sends findings to Orchestrator via gRPC
   ├─ UpdateScanStatus(RUNNING)
   ├─ CreateFindings(findings)
   ├─ UpdateFindingsCount(count)
   └─ UpdateScanStatus(COMPLETED/FAILED)
   │
5. Exit (K8s cleans up pod)
```

**Note:** Runner does NOT communicate with Storage Service directly. It only uses presigned URLs for S3 download and calls Orchestrator for all other operations.

## Configuration

Configuration is loaded from environment variables set by the Orchestrator:

### Required Environment Variables

```bash
# Scan metadata
SCAN_ID=uuid-1234-5678-...
SOURCE_ARTIFACT_ID=uuid-abcd-efgh-...
ORGANIZATION_ID=uuid-org-...
PROJECT_ID=uuid-proj-...

# Service endpoints
ORCHESTRATOR_ENDPOINT=cloudscan-orchestrator.cloudscan.svc.cluster.local:9999
SOURCE_DOWNLOAD_URL=https://s3.amazonaws.com/bucket/artifact-id?presigned-params...

# Scan configuration
SCAN_TYPES=sast,sca,secrets,license  # Comma-separated

# Repository info (optional)
GIT_URL=https://github.com/org/repo
GIT_BRANCH=main
GIT_COMMIT=abc123def

# Directories
WORK_DIR=/workspace
RESULTS_DIR=/results

# Timeouts
SCAN_TIMEOUT=1800        # 30 minutes
DOWNLOAD_TIMEOUT=300     # 5 minutes

# Logging
LOG_LEVEL=info
```

## Building

### Build Linux Binaries

```bash
make linux
```

This creates:
- `cloudscan-runner-amd64` (x86_64 Linux binary)
- `cloudscan-runner-arm64` (ARM64 Linux binary)

### Build Docker Image

```bash
docker build --build-arg TARGETARCH=amd64 -t cloudscan-runner:latest .
```

## Docker Image Structure

The Dockerfile:
1. Uses Ubuntu 22.04 as base
2. Installs all scanner tools (Semgrep, Trivy, TruffleHog, ScanCode)
3. Copies pre-built binary from `make linux`
4. Runs as non-root user `cloudscan`
5. Executes scanner runner on container start

## Development

### Project Structure

```
cloudscan-runner/
├── cmd/
│   └── main.go                    # Entry point
├── internal/
│   ├── config/
│   │   └── config.go              # Config from env vars
│   ├── downloader/
│   │   └── downloader.go          # S3 download & extract
│   ├── orchestrator/
│   │   └── client.go              # gRPC client
│   └── scanners/
│       ├── scanner.go             # Scanner interface
│       ├── semgrep.go             # SAST scanner
│       ├── trivy.go               # SCA scanner
│       ├── trufflehog.go          # Secrets scanner
│       └── scancode.go            # License scanner
├── Dockerfile
├── Makefile
└── go.mod
```

### Testing Locally

Set required environment variables and run:

```bash
export SCAN_ID=test-scan-id
export SOURCE_DOWNLOAD_URL=https://...presigned-url...
export ORCHESTRATOR_ENDPOINT=localhost:9999
export SCAN_TYPES=sast,sca
export ORGANIZATION_ID=test-org
export PROJECT_ID=test-project
export SOURCE_ARTIFACT_ID=test-artifact

./cloudscan-runner-amd64
```

## Parallel Execution

All scanners run concurrently using goroutines:

```go
func runScannersParallel(ctx context.Context, scanners []Scanner, sourceDir string) []*Result {
    var wg sync.WaitGroup
    results := make([]*Result, len(scanners))

    for i, scanner := range scanners {
        wg.Add(1)
        go func(idx int, scnr Scanner) {
            defer wg.Done()
            findings, err := scnr.Scan(ctx, sourceDir)
            results[idx] = &Result{
                Findings:    findings,
                ScanType:    scnr.ScanType(),
                ScannerName: scnr.Name(),
                Error:       err,
            }
        }(i, scanner)
    }

    wg.Wait()
    return results
}
```

This allows scanning to complete in ~5-7 minutes instead of ~13 minutes sequential execution.

## License

Apache 2.0