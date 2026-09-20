# Trinetra Cryptographic Detection Accuracy Benchmark

> *"A scanner that cannot state its false-positive rate cannot be trusted."*

This document publishes the precision, recall, key-size resolution, and cipher-mode resolution metrics for the Trinetra detection pipeline against our verified multi-language fixture corpus.

---

## 1. Methodology

Detection accuracy measures **the pipeline as integrated**: rule packs, pattern extractors, message-interpolation parsers, and the CBOM ingest validator together. Upstream claims from underlying engines (Semgrep, Syft) are never accepted as Trinetra's own without empirical verification on ground truth.

### Corpora

1. **Positive Fixture Corpus (`tests/fixtures/positive/`)**:
   Contains confirmed real-world cryptographic invocations across five languages:
   - **Python** (`crypto_usage.py`): RSA keygen (1024, 2048), AES (CBC, GCM), MD5, SHA-256, ECDSA, 3DES
   - **Go** (`crypto_usage.go`): RSA (2048), MD5, AES-GCM, ECDSA P-256
   - **Java** (`CryptoUsage.java`): AES (CBC, GCM, ECB), MD5, RSA
   - **JavaScript** (`crypto_usage.js`): MD5, SHA-256, AES-256-CBC, RSA
   - **C** (`crypto_usage.c`): OpenSSL MD5, RSA-2048, AES

2. **Negative Fixture Corpus (`tests/fixtures/negative/`)**:
   Contains non-cryptographic code designed to trigger false positives in naive regex-based scanners (variable names like `md5_hash_table_size`, comments mentioning `RSA`, standard string utilities, and math libraries).

---

## 2. Benchmark Metrics

| Metric | Target | Actual | Meaning |
|---|---|---|---|
| **Precision** | **100.0%** | **100.0%** | No false positives on the negative corpus (`TP / (TP + FP)`) |
| **Recall** | **100.0%** | **100.0%** | Every human-confirmed crypto usage site was detected (`TP / (TP + FN)`) |
| **Key Size Resolution** | **100.0%** | **100.0%** | Key sizes (1024, 2048, 256) extracted and interpolated into finding metadata |
| **Mode Resolution** | **100.0%** | **100.0%** | Cipher modes (`CBC`, `GCM`, `ECB`) parsed and preserved |

---

## 3. Results Summary

```text
Trinetra source-detection accuracy
====================================================
  expected sites          23
  detected (true pos)     23
  missed (false neg)      0
  false positives         0

  precision               100.0%
  recall                  100.0%
  key size resolution     100.0%  (5/5)
  mode resolution         100.0%  (6/6)

RESULT: PASS
```

### Key Invariants Verified

- **Zero False Positives**: No findings emitted on negative fixtures.
- **R19 Full Parameter Capture**: Weak/ECB cipher modes and small RSA key sizes (1024-bit) are classified with exact parameter values rather than generic algorithm names.
- **No Inferred Defaults (P3)**: Missing key sizes or cipher modes are preserved as unobserved rather than defaulted.

---

## 4. CI/CD Automated Execution

The benchmark script runs in CI pipelines to guard against detection regression:

```bash
# Human-readable stdout
python scripts/benchmark_accuracy.py

# Machine-readable JSON output for automated gating
python scripts/benchmark_accuracy.py --json

# JUnit XML output for CI test reporting
python scripts/benchmark_accuracy.py --junit-xml reports/accuracy-junit.xml
```
