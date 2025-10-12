# cloudscan-runner

> Scanner runner for CloudScan - executes security scans inside Kubernetes Jobs

## Scanners Included

**SAST:** Semgrep
**SCA:** Trivy
**Secrets:** TruffleHog
**License:** ScanCode Toolkit

## Flow

1. Receive job via K8s Job spec
2. Download source code from storage service
3. Run configured scanners (parallel execution)
4. Parse results to SARIF format
5. Upload findings to storage service
6. Update scan status via gRPC
7. Exit (K8s cleans up pod)

## Docker Image

```dockerfile
FROM ubuntu:22.04

# Install scanners
RUN pip install semgrep trufflehog scancode-toolkit
RUN wget trivy && mv trivy /usr/local/bin/

# Copy runner binary
COPY runner /usr/local/bin/runner

CMD ["/usr/local/bin/runner"]
```

## Configuration

```bash
# Passed via K8s Job env vars
SCAN_ID=scan-123
SCAN_TYPES=sast,sca,secrets,license
ORCHESTRATOR_URL=cloudscan-orchestrator:9999
STORAGE_URL=cloudscan-storage:8082
```

## Parallel Execution

```go
var wg sync.WaitGroup
wg.Add(4)

go func() { defer wg.Done(); runSemgrep() }()
go func() { defer wg.Done(); runTrivy() }()
go func() { defer wg.Done(); runTruffleHog() }()
go func() { defer wg.Done(); runScanCode() }()

wg.Wait()
```