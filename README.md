# LLRP Discovery Service

A lightweight Go service for discovering LLRP-compatible RFID readers on a network.

## Features

- **CIDR Subnet Scanning**: Scan entire network ranges using CIDR notation (e.g., `192.168.1.0/24`)
- **Parallel Probing**: Concurrent network scanning with configurable limits
- **LLRP Protocol**: Validates LLRP connectivity on port 5084
- **REST API**: Simple HTTP API for triggering discovery and retrieving results
- **Docker Support**: Multi-platform Docker images (amd64, arm64)
- **Lightweight**: ~8-10MB Docker image using multi-stage builds

## Quick Start

### Docker

```bash
docker run -p 8080:8080 \
  -e SUBNETS="192.168.1.0/24" \
  ghcr.io/trakrf/llrp-discovery:latest
```

### Docker Compose

```yaml
services:
  llrp-discovery:
    image: ghcr.io/trakrf/llrp-discovery:latest
    network_mode: host
    environment:
      - SUBNETS=192.168.1.0/24,10.0.0.0/24
      - ASYNC_LIMIT=1000
      - TIMEOUT_SECONDS=5
      - SCAN_PORT=5084
      - HTTP_PORT=8080
```

### Local Build

```bash
go build -o llrp-discovery
./llrp-discovery
```

## API Endpoints

### `GET /discover`

Triggers a network scan and returns discovered readers.

**Query Parameters:**
- `subnets` (optional): Comma-separated CIDR ranges. Defaults to env var `SUBNETS`

**Example:**
```bash
curl "http://localhost:8080/discover?subnets=192.168.1.0/24"
```

**Response:**
```json
{
  "readers": [
    {
      "ip": "192.168.1.135",
      "hostname": "SpeedwayR-12-CC-E1",
      "port": 5084
    }
  ],
  "scanned": 254,
  "duration_ms": 1234
}
```

### `GET /health`

Health check endpoint.

```bash
curl http://localhost:8080/health
```

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SUBNETS` | `192.168.1.0/24` | Comma-separated CIDR subnet list |
| `ASYNC_LIMIT` | `1000` | Maximum concurrent network probes |
| `TIMEOUT_SECONDS` | `5` | Timeout per IP probe (seconds) |
| `SCAN_PORT` | `5084` | LLRP port to scan |
| `HTTP_PORT` | `8080` | HTTP API port |
| `MAX_DURATION_SECONDS` | `300` | Maximum discovery duration (5 minutes) |

## Use with TrakRF Keypr

Add to `docker-compose.prod.yml`:

```yaml
services:
  llrp-discovery:
    image: ghcr.io/trakrf/llrp-discovery:latest
    network_mode: host
    restart: unless-stopped
    environment:
      - SUBNETS=192.168.1.0/24
      - HTTP_PORT=8082
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8082/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```

Then call from your application:
```bash
curl http://localhost:8082/discover
```

## Attribution

This project's discovery algorithm is derived from the [EdgeX Foundry device-rfid-llrp-go](https://github.com/edgexfoundry/device-rfid-llrp-go) service, specifically from `internal/driver/discover.go`.

**Original Copyright:** Copyright 2020 Intel Corporation
**Original License:** Apache License 2.0

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

Copyright 2025 TrakRF
