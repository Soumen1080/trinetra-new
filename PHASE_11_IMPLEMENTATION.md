# Phase 11A & 11B Implementation Summary

## Overview

This document summarizes the implementation of Phase 11A (Live TLS/SSH observation) and Phase 11B (Binary analysis, CVE detection, PII classification) coverage extensions for Trinetra.

## Phase 11A: Live TLS Scanner ✅

### Implementation

Created a new `scanner-egress` service that observes live protocol negotiation on network endpoints. This is the fourth scanner service, isolated on `scanner-egress` because it requires outbound network access.

**Key Components:**

1. **Service Structure** (`scanners/egress/`)
   - Go module following the same pattern as other scanners
   - Uses shared `cbom-go` contract for consistency
   - Separate blast radius from file-based scanners

2. **TestSSL Engine** (`testssl.go`)
   - Wraps testssl.sh for TLS protocol observation
   - Detects protocol versions (TLS 1.3, 1.2, 1.1, 1.0; SSLv3)
   - Reports cipher suites negotiated on the wire
   - Identifies certificate key types and sizes
   - Detects hybrid PQC KEX (X25519MLKEM768)
   - **All findings emit with `is_observed=true`**

3. **SSH Engine** (`ssh.go`)
   - Built-in SSH server probing (no external dependencies)
   - Detects host key types (RSA, ECDSA, Ed25519)
   - Estimates key sizes from marshaled public keys
   - Note: Full KEX/MAC detection requires enhanced library support

4. **Backend Integration**
   - Added `IsObserved` field to `cbom.Finding` struct
   - Emits `trinetra:is-observed` property in CycloneDX output
   - Updated Python ingest to read and store `is_observed` flag
   - Schema already supported `is_observed` on `ProtocolDetail`

5. **Observed vs Declared Comparison** (`observed_comparison.py`)
   - Compares live observations against declared configuration
   - Identifies three categories:
     - **Matched**: Both declared and observed (expected)
     - **Observed-only**: Accepted on wire but not declared (critical!)
     - **Declared-only**: Configured but not seen (informational)
   - Flags weak protocols (TLS 1.0/1.1, SSLv3) with extra warnings
   - API endpoint: `GET /api/v1/applications/{id}/observed-vs-declared`

### Why This Matters

**A load balancer can accept TLS 1.0 even when the backend forbids it.** Only live observation detects this mismatch. This is the highest-value coverage extension because it answers what is *actually negotiated on the wire*, not what is intended or installed.

### Configuration

```bash
# Required
export TRINETRA_SCANNER_TOKEN="<32+ character token>"

# Optional
export TRINETRA_TESTSSL_BINARY="/path/to/testssl.sh"  # default: testssl.sh
export TRINETRA_SCANNER_ADDR=":8080"                   # default: :8080
```

### Usage

```bash
# Scan a TLS endpoint
curl -X POST http://scanner-egress:8080/scan \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "scan_id": "uuid-here",
    "target_ref": "example.com:443"
  }'

# Get observed vs declared comparison
curl http://api:8080/api/v1/applications/app-123/observed-vs-declared
```

---

## Phase 11B: Binary Scanner ✅

### Implementation

Created a new `scanner-binary` service that analyzes compiled binaries, detects CVEs, and classifies sensitive data. Runs on its own queue because binary analysis is slow and resource-intensive.

**Key Components:**

1. **Service Structure** (`scanners/binary/`)
   - Go module with multi-engine architecture
   - Separate from source scanner due to different resource profile
   - Follows same cbom-go contract

2. **Ghidra Engine** (`ghidra.go`)
   - Detects crypto constants in stripped binaries:
     - AES S-box (256-byte permutation table)
     - SHA-256 IVs (8×32-bit constants)
     - MD5 magic constants (4×32-bit values)
     - DES S-boxes (heuristic)
   - Identifies crypto API calls (OpenSSL, mbedtls, BCrypt, etc.)
   - Extracts linked crypto libraries
   - Supports ELF, PE, Mach-O formats
   - Companion Java script: `scripts/CryptoDetector.java`

3. **OSV-Scanner Engine** (`osv.go`)
   - CVE detection in dependencies
   - Provides **present-tense risk** alongside quantum risk
   - Supports Go, Python, Node.js, Rust, Java, Ruby, PHP
   - CVE IDs stored in `snippet` field for filtering
   - Exits 1 when vulnerabilities found (expected, not error)

4. **Presidio Engine** (`presidio.go`)
   - NER-based PII detection via Microsoft Presidio
   - Detects: SSN, credit cards, names, emails, phone numbers, etc.
   - Strengthens X risk tier (what data is at risk)
   - Connects to Presidio Analyzer service (HTTP REST API)
   - Aggregates counts per file, not content (privacy)
   - 1MB file size limit to avoid performance issues

5. **Binary Format Detection** (`ghidra.go`)
   - Magic byte detection for ELF, PE, Mach-O
   - Executable bit checking
   - Extension-based hints (.exe, .dll, .so, .dylib)

### Why This Matters

- **Ghidra**: Detects crypto in binaries where source code is unavailable
- **OSV**: Shows *what is vulnerable today* alongside quantum risk forecasting
- **Presidio**: Identifies *what data would be at risk* if encryption breaks

All three remain **evidence sources, never verdict sources** (§7.1).

### Configuration

```bash
# Required
export TRINETRA_SCANNER_TOKEN="<32+ character token>"

# Ghidra (optional, skipped if missing)
export TRINETRA_GHIDRA_BINARY="/opt/ghidra/support/analyzeHeadless"
export TRINETRA_GHIDRA_SCRIPT_PATH="/opt/trinetra/ghidra-scripts"

# OSV-Scanner (optional, skipped if missing)
export TRINETRA_OSV_BINARY="osv-scanner"

# Presidio (optional, skipped if missing)
export TRINETRA_PRESIDIO_URL="http://localhost:5002"
```

### Setup

**Ghidra:**
```bash
# Install Ghidra from https://ghidra-sre.org/
# Copy scripts/CryptoDetector.java to script directory
export TRINETRA_GHIDRA_BINARY=/opt/ghidra/support/analyzeHeadless
export TRINETRA_GHIDRA_SCRIPT_PATH=$(pwd)/scanners/binary/scripts
```

**OSV-Scanner:**
```bash
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

**Presidio:**
```bash
docker run -d -p 5002:5002 mcr.microsoft.com/presidio-analyzer
```

### Usage

```bash
# Scan a directory containing binaries
curl -X POST http://scanner-binary:8080/scan \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "scan_id": "uuid-here",
    "target_ref": "path/to/binaries"
  }'
```

---

## Architecture Decisions

### Why Separate Services?

**Five scanner services, not one:**

1. **source**: Source code analysis (no external access needed)
2. **container**: Container image analysis (needs registry egress)
3. **cloudhsm**: Cloud and HSM scanning (holds cloud credentials)
4. **egress**: Live TLS/SSH observation (needs network egress)
5. **binary**: Binary analysis (slow, resource-intensive)

**Each has a different blast radius.** A compromise in one cannot reach the others.

### Why Observed vs Declared?

Configuration files state *intent*. Live observation states *fact*. The two routinely differ:

- A correctly configured backend may sit behind a load balancer that still accepts TLS 1.0
- A proxy may negotiate weak cipher suites even when the application forbids them
- SSH configuration may allow weak KEX algorithms at the network layer

Only live observation detects these mismatches, and a mismatch is often the most actionable finding in the entire scan.

### Why CVE + Quantum Risk?

Trinetra's core value is **future quantum risk** assessment. But organizations also need **present-tense risk** (what's vulnerable *today*). OSV-Scanner provides the latter, clearly separated so the two are never confused:

- Quantum risk: "This will break when quantum computers scale"
- CVE risk: "This is exploitable right now"

Both are evidence sources; neither is a verdict.

### Why Presidio?

Regex patterns detect some PII, but NER (Named Entity Recognition) is more accurate. Presidio strengthens the X risk tier by identifying *what data is at risk* if encryption is compromised:

- Credit cards → financial risk
- SSNs → identity theft risk
- Medical records → HIPAA compliance risk

This context helps prioritize remediation.

---

## Testing

### Unit Tests

```bash
# Egress scanner
cd scanners/egress
go test ./internal/engine/...

# Binary scanner
cd scanners/binary
go test ./internal/engine/...

# Backend comparison logic
cd backend
pytest tests/services/test_observed_comparison.py
```

### Integration Tests

Require external dependencies (testssl.sh, Ghidra, OSV, Presidio):

```bash
# Set up environment
export TRINETRA_TESTSSL_BINARY=/opt/testssl/testssl.sh
export TRINETRA_GHIDRA_BINARY=/opt/ghidra/support/analyzeHeadless
export TRINETRA_GHIDRA_SCRIPT_PATH=$(pwd)/scanners/binary/scripts
export TRINETRA_PRESIDIO_URL=http://localhost:5002

# Run integration tests
go test -tags=integration ./scanners/egress/...
go test -tags=integration ./scanners/binary/...
```

---

## Deliverables

### Code

- ✅ `scanners/egress/` - Live TLS/SSH scanner service
- ✅ `scanners/binary/` - Binary analysis scanner service
- ✅ `backend/app/services/observed_comparison.py` - Comparison logic
- ✅ `backend/app/api/routes.py` - Comparison endpoint
- ✅ Updated `cbom-go` to support `is_observed` flag

### Documentation

- ✅ `scanners/egress/README.md` - Egress scanner documentation
- ✅ `scanners/binary/README.md` - Binary scanner documentation
- ✅ `scanners/README.md` - Updated with new scanners
- ✅ `PHASE_11_IMPLEMENTATION.md` - This document

### Tests

- ✅ `tests/services/test_observed_comparison.py` - Comparison logic tests
- ✅ Unit test structure in place for all engines

---

## Deployment Notes

### Docker Compose

Add to `docker-compose.yml`:

```yaml
  scanner-egress:
    build: ./scanners/egress
    environment:
      - TRINETRA_SCANNER_TOKEN=${SCANNER_TOKEN}
      - TRINETRA_TESTSSL_BINARY=/opt/testssl/testssl.sh
    volumes:
      - artifact-store:/artifact-store
    networks:
      - scanner-egress

  scanner-binary:
    build: ./scanners/binary
    environment:
      - TRINETRA_SCANNER_TOKEN=${SCANNER_TOKEN}
      - TRINETRA_GHIDRA_BINARY=/opt/ghidra/support/analyzeHeadless
      - TRINETRA_GHIDRA_SCRIPT_PATH=/opt/trinetra/ghidra-scripts
    volumes:
      - artifact-store:/artifact-store
      - scan-workdir:/scan-workdir:ro
    networks:
      - scanner-internal
```

### Security Considerations

1. **Egress Scanner**
   - Runs on isolated network with egress access
   - No access to source code or cloud credentials
   - Timeout enforcement on all network operations

2. **Binary Scanner**
   - Ghidra runs in sandboxed headless mode
   - No network access during analysis
   - Temporary projects cleaned up after scan

3. **Credentials**
   - Presidio runs as separate service (no credentials in scanner)
   - OSV-Scanner reads public CVE database (no auth)
   - Scanner tokens ≥32 characters, compared via SHA-256 digest

---

## Future Enhancements

### Phase 11C (Deferred Coverage Gaps)

- **11C.1**: Transitive dependency scanning
- **11C.3**: Verify cbomkit-theia end-to-end
- **11C.5**: Test against real AWS account

### UI Integration

- Observed vs Declared dashboard view
- CVE risk vs Quantum risk side-by-side charts
- PII detection summary in context panel

### Performance

- Worker pools for parallel binary analysis
- CBOM caching for unchanged binaries
- Incremental rescans for large repositories

---

## Conclusion

Phase 11A and 11B extend Trinetra's coverage to live protocol observation, binary analysis, CVE detection, and PII classification. Each extension follows the architecture (separate blast radius, evidence not verdicts) and maintains the invariants (honest gaps, immutable artifacts, no secrets stored).

**The observed vs declared comparison is the highest-value coverage gain:** it detects mismatches between what is configured and what is actually negotiated on the wire, which is often the most immediately actionable finding in the entire scan.
