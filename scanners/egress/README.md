# Egress Scanner (Phase 11A)

Live TLS/SSH observation service. Connects to endpoints and reports what is
actually negotiated on the wire.

## Why a separate service?

This scanner needs **outbound network access** — a different blast radius than
the file-based scanners. It runs on `scanner-egress` rather than
`scanner-internal`, so a vulnerability here cannot reach the source tree or
cloud credentials.

## What it detects

Every finding this scanner produces has `is_observed=true`, distinguishing it
from declared configuration that the config engine reads from files.

**Declared and observed crypto routinely differ.** A load balancer in front of a
correctly configured service can still accept TLS 1.0, and only live observation
detects this.

### TLS (testssl.sh)

- Protocol versions (TLS 1.3, 1.2, 1.1, 1.0; SSLv3)
- Cipher suites negotiated
- Certificate key types and sizes (RSA-2048, ECDSA-P256, Ed25519)
- Hybrid PQC KEX (X25519MLKEM768)

### SSH (built-in)

- Host key types and sizes
- KEX algorithms (when observable)
- MAC algorithms (when observable)

Note: The golang.org/x/crypto/ssh package does not expose negotiated algorithms
directly. Full KEX/MAC detection requires either forking the library or
capturing handshakes at the network level.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `TRINETRA_SCANNER_TOKEN` | (required) | Authentication token (≥32 chars) |
| `TRINETRA_SCANNER_ADDR` | `:8080` | Listen address |
| `TRINETRA_ARTIFACT_STORE` | `/artifact-store` | Where to write CBOMs |
| `TRINETRA_TESTSSL_BINARY` | `testssl.sh` | Path to testssl.sh |

## Running

```sh
# Install testssl.sh
git clone https://github.com/drwetter/testssl.sh.git /opt/testssl
export TRINETRA_TESTSSL_BINARY=/opt/testssl/testssl.sh

# Run the scanner
export TRINETRA_SCANNER_TOKEN=$(openssl rand -hex 32)
go run ./cmd/main.go
```

## Scan request format

```json
{
  "scan_id": "uuid",
  "target_ref": "example.com:443"
}
```

The `target_ref` is the endpoint to probe (host:port for TLS, host:22 for SSH).

## Output

A CycloneDX 1.6 CBOM with:
- `protocol` artefacts with `trinetra:is-observed=true`
- `certificate` artefacts for observed server keys
- Coverage gaps when engines are unavailable

## Observed vs Declared

The backend `/api/v1/applications/{id}/observed-vs-declared` endpoint compares
this scanner's findings against config-engine findings:

- **Matched**: Protocol is both declared and observed
- **Observed-only**: Protocol is accepted on the wire but not declared in config
  (critical — indicates load balancer/proxy mismatch)
- **Declared-only**: Protocol is configured but not seen in live traffic
  (informational)

## Testing

```sh
# Unit tests
go test ./internal/engine/...

# Integration test against a live endpoint
export TRINETRA_TESTSSL_BINARY=/opt/testssl/testssl.sh
go test -tags=integration ./...
```

## Invariants

- **Every finding has `is_observed=true`** — enforced at construction
- **No credentials stored** — endpoints are public; no auth material persists
- **Timeout enforced** — network operations have reasonable deadlines
- **Failures reported as gaps** — an unreachable endpoint is a gap, not silence
