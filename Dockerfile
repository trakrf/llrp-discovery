# Multi-stage build for minimal final image
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod ./

# Download dependencies
RUN go mod download

# Copy source code
COPY *.go ./

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o llrp-discovery .

# Final stage - minimal image
FROM alpine:latest

# Add ca-certificates for HTTPS (if needed) and wget for healthcheck
RUN apk --no-cache add ca-certificates wget

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/llrp-discovery .

# Expose default HTTP port
EXPOSE 8080

# Run as non-root user
RUN adduser -D -u 1000 llrp
USER llrp

# Set default environment variables
ENV SUBNETS="192.168.1.0/24" \
    ASYNC_LIMIT="1000" \
    TIMEOUT_SECONDS="5" \
    SCAN_PORT="5084" \
    HTTP_PORT="8080" \
    MAX_DURATION_SECONDS="300"

CMD ["./llrp-discovery"]
