# Binary Scanner (Phase 11B)

Binary analysis, CVE detection, and PII classification service.

## Why a separate service?

Binary analysis is **slow and resource-intensive**, with a different profile than
source scanning. It runs on its own queue so it does not block faster scans.

## What it detects

Following §7.4, each engine remains an **evidence source, never a verdict
source**. A CVE is reported as evidence; Presidio detects PII to strengthen the
X risk tier (what data is at risk).

### Ghidra

Crypto constants and API calls in **stripped binaries**:

- **AES S-box** (256-byte permutation table)
- **SHA-256 initialization vectors** (8×32-bit constants)
- **MD5 magic constants** (4×32-bit values)
- **DES S-boxes** (heuristic detection)
- **Crypto API calls** (OpenSSL, mbedtls, BCrypt, etc.)
- **Linked crypto libraries** (libcrypto, libssl, etc.)

Supports ELF, PE, and Mach-O binaries.

### OSV-Scanner

CVE detection in dependencies. Provides **present-tense risk** (what is
vulnerable today) alongside Trinetra's future quantum risk verdict. The two are
kept clearly separated so they are never confused.

Supports:
- Go modules
- Python requirements
- Node.js packages
- Rust crates
- Java JARs
- Ruby gems
- PHP Composer

### Presidio

NER-based sensitive data classification, strengthening the X evidence tier beyond
regex:

- Credit card numbers
- Social Security Numbers (SSN)
- Email addresses
- Phone numbers
- Names, locations
- Medical license numbers
- Bank account numbers
- IP addresses
- Custom entity types

Presidio runs as a separate service (Python REST API). The scanner submits text
and receives entity classifications.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `TRINETRA_SCANNER_TOKEN` | (required) | Authentication token (≥32 chars) |
| `TRINETRA_SCANNER_ADDR` | `:8080` | Listen address |
| `TRINETRA_INPUT_ROOT` | `/scan-workdir` | Read-only scan input root |
| `TRINETRA_ARTIFACT_STORE` | `/artifact-store` | Where to write CBOMs |
| `TRINETRA_GHIDRA_BINARY` | `analyzeHeadless` | Path to Ghidra headless analyzer |
| `TRINETRA_GHIDRA_SCRIPT_PATH` | `/opt/trinetra/ghidra-scripts` | Location of CryptoDetector.java |
| `TRINETRA_OSV_BINARY` | `osv-scanner` | Path to osv-scanner |
| `TRINETRA_PRESIDIO_URL` | `http://localhost:5002` | Presidio Analyzer endpoint |

## Setup

### Ghidra

1. Install Ghidra: https://ghidra-sre.org/
2. Copy `scripts/CryptoDetector.java` to the script directory
3. Set `TRINETRA_GHIDRA_BINARY` to the `analyzeHeadless` path
4. Set `TRINETRA_GHIDRA_SCRIPT_PATH` to where you placed the script

### OSV-Scanner

```sh
# Install via go
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Or download binary from GitHub releases
curl -LO https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64
chmod +x osv-scanner_linux_amd64
sudo mv osv-scanner_linux_amd64 /usr/local/bin/osv-scanner
```

### Presidio

```sh
# Run Presidio Analyzer as a Docker container
docker run -d -p 5002:5002 mcr.microsoft.com/presidio-analyzer

# Or install from source
pip install presidio-analyzer
python -m presidio_analyzer
```

## Running

```sh
export TRINETRA_SCANNER_TOKEN=$(openssl rand -hex 32)
export TRINETRA_GHIDRA_BINARY=/opt/ghidra/support/analyzeHeadless
export TRINETRA_GHIDRA_SCRIPT_PATH=$(pwd)/scripts

go run ./cmd/main.go
```

## Scan request format

```json
{
  "scan_id": "uuid",
  "target_ref": "path/to/scan"
}
```

The `target_ref` is resolved against `TRINETRA_INPUT_ROOT` and must not escape it.

## Output

A CycloneDX 1.6 CBOM with:
- `implementation` artefacts for crypto constants
- `call` artefacts for API calls
- `library` artefacts for dependencies (with CVE IDs in snippet)
- `data` artefacts for PII detections
- Coverage gaps when engines are unavailable

## Performance

Binary analysis is slow:
- Ghidra: ~30 seconds to 2 minutes per binary
- OSV-Scanner: depends on dependency count
- Presidio: depends on file count and size

Limit binary size and file counts for reasonable scan times. Use separate queues
or worker pools for production deployments.

## Testing

```sh
# Unit tests
go test ./internal/engine/...

# Integration test (requires Ghidra, OSV, Presidio)
export TRINETRA_GHIDRA_BINARY=/opt/ghidra/support/analyzeHeadless
export TRINETRA_GHIDRA_SCRIPT_PATH=$(pwd)/scripts
export TRINETRA_PRESIDIO_URL=http://localhost:5002
go test -tags=integration ./...
```

## Invariants

- **Libraries never carry algorithms** — enforced by cbom.Finding.Normalise()
- **CVE IDs stored in snippet field** — distinguishable from crypto findings
- **PII counts, not content** — Presidio detections are aggregated per file
- **Binaries identified by magic bytes** — not just extensions
- **File size limits enforced** — Presidio skips files >1MB
- **Ghidra projects are ephemeral** — cleaned up after each scan
- **Missing engines are gaps, not silence** — coverage must be honest
