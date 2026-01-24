# Multi-stage build for Go service
# Security-hardened container for zero-trust environment

# Build stage
FROM golang:1.21-alpine AS builder

# Install security updates and required packages
RUN apk update && apk add --no-cache \
    ca-certificates \
    git \
    tzdata \
    && update-ca-certificates

# Create non-root user for build
RUN adduser -D -g '' appuser

# Set working directory
WORKDIR /build

# Copy go mod files first (better caching)
COPY go.mod go.sum ./
RUN go mod download
RUN go mod verify

# Copy source code
COPY . .

# Build the binary with security hardening
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o banking-core-service \
    main.go

# Production stage - Distroless base image
FROM gcr.io/distroless/static:nonroot

# Copy certificates and timezone data
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary
COPY --from=builder /build/banking-core-service /app/banking-core-service

# Use non-root user (distroless provides 'nonroot' user)
USER nonroot:nonroot

# Create volume for temporary data (if needed)
VOLUME ["/tmp"]

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/banking-core-service", "--health-check"]

# Set environment variables
ENV PORT=8080 \
    METRICS_PORT=9090 \
    LOG_LEVEL=info \
    LOG_FORMAT=json

# Run the binary
ENTRYPOINT ["/app/banking-core-service"]