# Dockerfile for CloudScan Runner
# Expects pre-built binary from make linux
FROM ubuntu:22.04

# Install runtime dependencies (minimal set needed for all scanners)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    wget \
    git \
    unzip \
    python3 \
    python3-pip \
    pkg-config \
    libicu-dev \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH

# Install Trivy (SCA scanner) - Standalone Binary
RUN TRIVY_VERSION=0.58.1 && \
    if [ "$TARGETARCH" = "arm64" ]; then TRIVY_ARCH="ARM64"; else TRIVY_ARCH="64bit"; fi && \
    wget -qO /tmp/trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    chmod +x /usr/local/bin/trivy && \
    rm /tmp/trivy.tar.gz

# Install TruffleHog (Secrets scanner) - Standalone Binary
RUN TRUFFLEHOG_VERSION=3.63.7 && \
    if [ "$TARGETARCH" = "arm64" ]; then TRUFFLEHOG_ARCH="arm64"; else TRUFFLEHOG_ARCH="amd64"; fi && \
    wget -qO /tmp/trufflehog.tar.gz https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TRUFFLEHOG_ARCH}.tar.gz && \
    tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog && \
    rm /tmp/trufflehog.tar.gz

# Install Python-based scanners using pip (official method, most reliable)
RUN pip3 install --no-cache-dir semgrep==1.99.0 scancode-toolkit-mini==32.3.0

# Verify all scanner installations
RUN trivy --version && \
    semgrep --version && \
    trufflehog --version && \
    scancode --version

# Create non-root user
RUN groupadd -g 1000 cloudscan && \
    useradd -u 1000 -g cloudscan -m -s /bin/bash cloudscan

WORKDIR /app

# Copy pre-built binary (expects cloudscan-runner-amd64 or cloudscan-runner-arm64)
COPY cloudscan-runner-${TARGETARCH} /app/cloudscan-runner

# Create necessary directories with proper permissions
RUN mkdir -p /workspace /results /tmp && \
    chown -R cloudscan:cloudscan /app /workspace /results /tmp && \
    chmod +x /app/cloudscan-runner

# Switch to non-root user
USER cloudscan

# Set default environment variables
ENV WORK_DIR=/workspace \
    RESULTS_DIR=/results \
    LOG_LEVEL=info

# Run the scanner runner
ENTRYPOINT ["/app/cloudscan-runner"]