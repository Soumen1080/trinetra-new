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
```

## Detection engines

Trinetra does not write its own detector. It runs maintained upstream engines
behind thin adapters, and §7.1 governs each one: **every upstream tool is a
source of evidence, never a source of verdicts.**

| Engine | Covers | Status |
|---|---|---|
| `SemgrepEngine` | Python, Java, Go, JS/TS, C/C++ — plus the PII→crypto taint analysis | Working |
| `CBOMkitEngine` | Java, Python, Go (symbol-resolved) | Set `TRINETRA_CBOMKIT_BINARY` |

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
go test ./cbom-go/... ./source/...

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
  one either.
