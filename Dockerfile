# Dockerfile for CloudScan Runner
# Expects pre-built binary from make linux
FROM alpine:3.19

# Install runtime dependencies and scanner tools
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    wget \
    git \
    python3 \
    py3-pip \
    npm \
    curl \
    bash

# Install scanner tools
ARG TARGETARCH

# Trivy for container/vulnerability scanning
#RUN TRIVY_VERSION=0.58.1 && \
#    if [ "$TARGETARCH" = "arm64" ]; then TRIVY_ARCH="ARM64"; else TRIVY_ARCH="64bit"; fi && \
#    wget -qO /tmp/trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz && \
#    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
#    chmod +x /usr/local/bin/trivy && \
#    rm /tmp/trivy.tar.gz

# Semgrep for SAST
#RUN pip3 install --no-cache-dir semgrep --break-system-packages

# TruffleHog for secrets scanning
#RUN wget -qO /tmp/trufflehog.tar.gz https://github.com/trufflesecurity/trufflehog/releases/download/v3.63.7/trufflehog_3.63.7_linux_${TARGETARCH}.tar.gz && \
#    tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog && \
#    chmod +x /usr/local/bin/trufflehog && \
#    rm /tmp/trufflehog.tar.gz

# ScanCode for license/dependency scanning
#RUN pip3 install --no-cache-dir scancode-toolkit --break-system-packages

# Create non-root user
RUN addgroup -g 1000 cloudscan && \
    adduser -D -u 1000 -G cloudscan cloudscan

WORKDIR /app

# Copy pre-built binary (expects cloudscan-runner-amd64 or cloudscan-runner-arm64)
COPY cloudscan-runner-${TARGETARCH} ./cloudscan-runner

# Create necessary directories with proper permissions
RUN mkdir -p /app/scans /app/results /tmp && \
    chown -R cloudscan:cloudscan /app /tmp

# Switch to non-root user
USER cloudscan

# Expose port if runner has HTTP endpoint
EXPOSE 8083

# Run the binary
ENTRYPOINT ["/app/cloudscan-runner"]