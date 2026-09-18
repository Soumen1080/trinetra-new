# Trinetra scanners

Go services that discover cryptographic assets and publish one immutable
CycloneDX 1.6 CBOM per scan. They detect; they never decide. Every judgement
lives behind the API (P1).

```
scanners/
  go.work                 Go workspace tying the modules together
  cbom-go/                shared module — one CBOM builder, one HTTP boundary
    cbom/                 Finding -> CycloneDX; sort, dedup, determinism, validation
    scannerapi/           auth, body cap, UUID validation, graceful shutdown
    targetpath/           path resolution — rejects anything escaping the input root
    artifactstore/        atomic, immutable writes
  source/                 the source-code scanner service
    internal/engine/      the pluggable detection-engine boundary
    cmd/                  the service binary
    cmd/gencbom/          regenerates the golden CBOM the Python tests read
  container/              the deployment-artefact scanner service
    internal/engine/      syft, x509/pki, config and theia engines
    cmd/                  the service binary
    cmd/gencbom/          regenerates the golden container CBOM
  cloudhsm/               the cloud and HSM scanner service
    internal/engine/      aws kms (sigv4) and pkcs#11 engines
    cmd/                  the service binary
    cmd/gencbom/          regenerates the golden cloud/HSM CBOM
```

Three services, not one, because their blast radii differ: the container scanner
needs registry egress to pull images, the cloud scanner holds cloud credentials,
and the source scanner needs neither. A compromised image pull cannot reach the
source tree, and neither can reach the cloud credentials.

## Detection engines

Trinetra does not write its own detector. It runs maintained upstream engines
behind thin adapters, and §7.1 governs each one: **every upstream tool is a
source of evidence, never a source of verdicts.**

**Source scanner:**

| Engine | Covers | Status |
|---|---|---|
| `SemgrepEngine` | Python, Java, Go, JS/TS, C/C++ — plus the PII→crypto taint analysis | Working |
| `CBOMkitEngine` | Java, Python, Go (symbol-resolved) | Set `TRINETRA_CBOMKIT_BINARY` |

**Container scanner:**

| Engine | Covers | Status |
|---|---|---|
| `SyftEngine` | crypto libraries, OS packages, language dependencies | Working |
| `PKIEngine` | X.509 certificates, public and private key material | Working |
| `ConfigEngine` | declared TLS versions, cipher suites, SSH algorithms | Working |
| `TheiaEngine` | image-layer certs, gitleaks secrets, Java security config | Set `TRINETRA_THEIA_BINARY` |
| `SBOMEngine` | components asserted by third-party CycloneDX 1.4–1.6 and SPDX 2.x | Working |

**Cloud/HSM scanner:**

| Engine | Covers | Status |
|---|---|---|
| `KMSEngine` | AWS KMS keys, specs, ownership | Working (verified against a live KMS API) |
| `AzureEngine` | Key Vault keys, Managed HSM | Working (`TRINETRA_AZURE_VAULT_URL` + `_TOKEN`) |
| `GCPEngine` | Cloud KMS keys, protection level | Working (`TRINETRA_GCP_PROJECT` + `_TOKEN`) |
| `PKCS11Engine` | HSM tokens, key objects, firmware, FIPS, PQC capability | Working (reads an inventory export) |

Azure and GCP take an **operator-supplied bearer token** rather than managing
credentials themselves. Both providers' token flows are interactive or
identity-bound and do not belong inside a scanner; passing a short-lived token
in also means Trinetra never holds a long-lived cloud secret.

Two decisions worth knowing. **PKCS#11 reads an operator-produced inventory
export rather than dlopen-ing a vendor `.so`**: loading a vendor native library
into a service that holds cloud credentials is unnecessary attack surface, HSMs
usually sit on networks the scanner cannot reach, and an export is reviewable by
a human first. **SigV4 is implemented in one file rather than pulling the AWS
SDK**: three read-only calls do not justify that dependency tree in a service
that must be vendorable for an air-gapped install.

Engines are **composed, not chosen**: the scanner runs every available engine and
merges their findings, because a CBOMkit hit and a Semgrep taint path about the
same call site are complementary evidence rather than duplicates. Where both
resolve the same site, the record that actually observed a key size wins the
merge — absent means unobserved, never zero (P3).

An engine whose binary is missing is **skipped and reported as a coverage gap**,
never silently ignored: a missing engine means a smaller inventory, and the user
has to be able to see that.

### Why CBOMkit is configuration rather than a hard dependency

`cbomkit-lib` is a Java **library**, and the rest of CBOMkit is a full-stack
server (Postgres + Quarkus + Vue) — neither is a scanner binary. The adapter is
written and tested against recorded CBOMkit output, so it activates by
configuration wherever a JRE and a CLI entry point exist, and a deployment
without one still gets a complete Semgrep inventory.

## Running

```sh
# Tests (no external services required)
go test ./cbom-go/... ./source/... ./container/... ./cloudhsm/...

# Rule-pack lint — enforces the two load-bearing rule constraints
python ../scripts/lint_rules.py ../rules

# Accuracy against the labelled corpus
python ../scripts/benchmark_accuracy.py

# Regenerate the golden CBOM (review the diff; never regenerate blindly)
go run ./source/cmd/gencbom \
  -input-root /tmp/in -ref target -rules ../rules -out /tmp/out
```

The service requires `TRINETRA_SCANNER_TOKEN` (≥32 characters, compared by
SHA-256 digest in constant time). Its port is never published to the host.

## The two rules every Semgrep rule obeys

Both are load-bearing, both are brittle by nature, and
`scripts/lint_rules.py` enforces them mechanically in CI rather than at review
time.

1. **Match call expressions, never bare identifiers.** A rule matching the token
   `rsa` flags `rsa = "some string"`. `tests/fixtures/negative` asserts that no
   rule does.
2. **Interpolate captured values into the message.** Semgrep OSS emits no
   `metavars` field, so the message string is the *only* channel that can carry a
   key size back to the adapter. A rule that forgets silently loses the size and
   the finding degrades to `NEEDS_CONTEXT`.

## Invariants worth knowing before changing anything here

- **Byte-identical output for identical input.** `bom-ref` values are
  content-derived and the timestamp is supplied by the caller, never read from
  the clock inside the builder. Golden-CBOM diffs are meaningless without this.
- **A library finding never carries an algorithm.** OpenSSL being installed
  proves a crypto implementation exists, not that any algorithm is used.
  Enforced in `Finding.Normalise`, in `Validate`, in Pydantic, and as a database
  CHECK constraint.
- **Validation happens twice** — in Go before the write, in Python on ingest.
  Schema drift on either side is caught at the boundary, not three layers deep.
- **Zero components is a valid result.** A repository genuinely free of
  cryptography is a real answer, not an error.
- **Artifacts are immutable.** A retried scan finds the existing document and
  resumes at ingest rather than overwriting it.
- **Evidence never carries a host path**, and client-facing errors never carry
  one either. Paths are forward-slashed everywhere, so a finding reads the same
  whether it was produced in a Linux container or on a Windows laptop.
- **Trinetra stores no secret material.** A private key yields a finding with a
  fingerprint, its parameters and `Redacted=true` — the key bytes are never read
  into a finding in the first place.
- **Declared crypto is not observed crypto.** Everything the config and
  container engines find is `is_observed=false`; only a live handshake
  (Phase 11A) observes, and a load balancer routinely accepts what a config
  forbids.
- **A library finding never implies an algorithm**, and `pqc_since: null` in the
  knowledge base means *not recorded*, never *unsupported*.
- **Metadata only from a KMS or an HSM.** Both exist so key material never
  leaves them; a scanner that extracted a key would defeat the control it is
  inventorying. Credentials are redacted in logs and never written anywhere.
- **Second-hand evidence is labelled as such.** A component an external SBOM
  asserted is `medium` confidence at best and says so in its evidence note —
  Trinetra did not observe it, and a finding's confidence must reflect who
  actually looked.
- **A missing cloud credential is a named gap, never silence.** "No keys found"
  is the most dangerous possible output for a cloud scanner, so every
  unavailable engine reports what it could not inventory and why.
