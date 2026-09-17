# Trinetra — Architecture, System Design & Codebase Structure

**Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)**
Smart India Hackathon 2026 · Problem Statement 26164 · NTRO · Blockchain & Cybersecurity

> Written for engineers joining the codebase, reviewers assessing the design, and
> anyone who has to deploy or extend the platform. It covers *what* the system is,
> *how* the pieces fit, *why* each boundary exists, and *where* every file lives.

---

## Table of contents

1. [What the system does](#1-what-the-system-does)
2. [Architectural principles](#2-architectural-principles)
3. [System topology](#3-system-topology)
4. [Component inventory](#4-component-inventory)
5. [The end-to-end request lifecycle](#5-the-end-to-end-request-lifecycle)
6. [Discovery layer — the three scanners](#6-discovery-layer--the-three-scanners)
7. [Upstream tooling — what Trinetra builds on](#7-upstream-tooling--what-trinetra-builds-on)
8. [The CBOM contract](#8-the-cbom-contract)
9. [Ingest and the context chain](#9-ingest-and-the-context-chain)
10. [The risk engine — two tracks](#10-the-risk-engine--two-tracks)
11. [The recommendation engine](#11-the-recommendation-engine)
12. [Data model](#12-data-model)
13. [Versioned policy profiles](#13-versioned-policy-profiles)
14. [API surface](#14-api-surface)
15. [Frontend — what the interface must present](#15-frontend--what-the-interface-must-present)
16. [Security architecture](#16-security-architecture)
17. [Deployment & runtime topology](#17-deployment--runtime-topology)
18. [Failure handling & reliability](#18-failure-handling--reliability)
19. [What must be tested](#19-what-must-be-tested)
20. [Building and extending](#20-building-and-extending)
21. [Design boundaries — what Trinetra will not do](#21-design-boundaries--what-trinetra-will-not-do)

---

## 1. What the system does

Trinetra scans an organisation's **source code, container images, and HSM / cloud
KMS metadata**, finds every cryptographic asset, scores how urgently each must be
replaced before quantum computers break it, and recommends a specific
standards-based quantum-safe replacement — all on one on-premise dashboard.

Four stages:

| Stage | What happens | Where it lives |
|:--|:--|:--|
| **1. Discover** | Scan code, images, HSM/KMS metadata → find algorithms, keys, certificates, libraries | `scanners/` (Go) |
| **2. Assess** | Derive the quantum attack resources for each algorithm + key size, compare against a versioned capability curve | `backend/app/engines/` |
| **3. Classify** | Compute first modelled break year, subtract migration time, combine with business criticality | `final_risk_engine.py` |
| **4. Recommend** | Propose a FIPS 203/204/205 replacement, gated by security category | `recommendation_engine.py` |

Output: a standardised **CycloneDX 1.6 CBOM** (Cryptography Bill of Materials)
plus an interactive dashboard and PDF report.

### The two questions every finding answers

```
"Will we run out of time to migrate?"        →  Mosca track      (X + Y > Z)
"When could this become attack-feasible?"    →  Resource track   (first t: P(t) ≥ Q)
```

These are **independent evidence**. They are combined **additively** into one
ranked score, never averaged, and every point traces back to one named input.

---

## 2. Architectural principles

Seven rules govern every design decision in this codebase. They are not
aspirational — they are enforced in code and visible in test names.

### P1 — Scanners detect, the backend decides

A scanner never scores, never classifies, never knows what a finding means. It
produces evidence in a fixed shape and stops. Every judgement lives behind the
API. This is why the container scanner can have network egress while the source
scanner has none: their blast radii are different, and neither can influence a
risk verdict.

### P2 — Engines are pure

Everything in `backend/app/engines/` is a pure function of
`(context, profile)`. No database, no HTTP, no clock reads that matter. This is
what makes `rescore_all` a genuine recalculation rather than a relabel —
identical inputs always produce identical output, so changing a policy profile
and re-running produces new, honest verdicts.

### P3 — Missing evidence produces *no number*, never a default

A factor with no evidence contributes **zero points and says so**. It is never
given a midpoint, because a silent default is indistinguishable from a
measurement. `AES.new(key, MODE_GCM)` does not state 128 or 256, so the finding
reports `NEEDS_CONTEXT` rather than guessing.

### P4 — Every number carries its provenance

Each context field records *which tier supplied it*
(`user` → `scanner_evidence` → `org_preset` → `unknown`). Each Q carries its
error-correction scheme, logical-qubit definition and physical error rate. A Q
without its assumptions is a number nobody can check.

### P5 — History is append-only

`risk_assessments` rows are never updated, only inserted.
`artefact.risk_assessment` returns the newest. This is what makes *"why was this
P0 last week?"* an answerable question.

### P6 — One canonical vocabulary, translated at the boundaries

Three vocabularies exist (Semgrep metadata, CycloneDX wire format, the engines).
**snake_case is canonical.** The Go scanner writes canonical → CycloneDX
(`vocab.go`); `vocab.py`
reads CycloneDX → canonical. The two tables must stay exact inverses of each other.

### P7 — Nothing leaves the private network

No dependency on any foreign or external cloud service. A defence or government
user will never upload a real cryptographic inventory to an outside system, so
the whole stack — database, queue, scanners, dashboard — runs inside one Compose
network.

---

## 3. System topology

Three layers, one contract between them.

```
┌──────────────────────────────────────────────────────────────────────┐
│  FRONTEND        React 19 · Vite 8 · TanStack Query · Tailwind       │
│                  nginx (prod) :8080  →  host :5173                   │
└───────────────────────────┬──────────────────────────────────────────┘
                            │  REST (cookie + CSRF)  ·  WebSocket
┌───────────────────────────▼──────────────────────────────────────────┐
│  BACKEND API     FastAPI · SQLAlchemy 2 · Pydantic v2      :8000     │
│    api/          routers, RBAC, CSRF, idempotency                    │
│    services/     orchestration, ingest, context, reports, progress   │
│    repositories/ the ONLY code that touches the database             │
│    ┌────────────────────────────────────────────────────┐            │
│    │ engines/  — PURE, no I/O, deterministic            │            │
│    │   risk_engine · mosca_engine · resource_engine     │            │
│    │   final_risk_engine · recommendation_engine        │            │
│    │   profiles/  versioned JSON policy + benchmarks    │            │
│    └────────────────────────────────────────────────────┘            │
│                                                                      │
│  WORKER          Celery, acks_late, concurrency 2                    │
└──────┬──────────────────────┬────────────────────┬───────────────────┘
       │ Bearer-token HTTP    │                    │
       │ (private network, ports never published)  │
┌──────▼────────┐  ┌──────────▼───────┐  ┌─────────▼──────────┐
│ scanner-source│  │ scanner-container│  │ scanner-cloud-hsm  │
│  Go + Semgrep │  │  Go + Syft/x509  │  │  Go + PKCS#11/KMS  │
│  no egress    │  │  egress allowed  │  │  no egress         │
└──────┬────────┘  └──────────┬───────┘  └─────────┬──────────┘
       └──────────────────────┴────────────────────┘
              all write CBOM → shared artifact-store volume
       ┌───────────────────────────────────────────────────┐
       │ PostgreSQL 16  :5433  │  Redis 7  :6379           │
       │  inventory, history   │  queue · sessions · pubsub│
       └───────────────────────────────────────────────────┘
```

### Networks

| Network | Members | Purpose |
|---|---|---|
| `default` | frontend, backend, worker, postgres, redis | Normal application traffic |
| `scanner-internal` | backend, worker, all three scanners | `internal: true` — **no external route at all** |
| `scanner-egress` | scanner-container only | The one service that must pull images |

Scanner ports are **never published to the host**. Only the backend and worker
can reach them, authenticated with a shared bearer token of ≥32 characters,
compared by SHA-256 digest in constant time.

### Volumes

| Volume | Written by | Read by | Contents |
|---|---|---|---|
| `pgdata` | postgres | postgres | The database |
| `artifact-store` | scanners | backend, worker | Generated CBOM documents, reports |
| `scan-workdir` | backend (git clone) | scanners (read-only) | Cloned scan targets, HSM fixtures |

Note the asymmetry: scanners mount `scan-workdir` **read-only** and
`artifact-store` read-write. They can never modify what they are asked to scan.

### Why three scanner services rather than one binary

Each has a different blast radius. The container scanner needs egress to pull
images; the source scanner needs none. Separating them means a compromised image
pull cannot reach your source tree. They share code through the `cbom-go` module
in a Go workspace — one CBOM builder, one HTTP boundary, one path resolver, three
deployable binaries.

---

## 4. Component inventory

| Component | Tech | Port | Role |
|---|---|---|---|
| **frontend** | React 19, TypeScript 7, Vite 8, Tailwind 3, Radix UI, TanStack Query 5, Zustand, Recharts, Motion | 5173→8080 | Dashboard, landing page, scan console |
| **backend** | Python 3.12, FastAPI, SQLAlchemy 2, Pydantic v2, Alembic | 8000 | API, RBAC, orchestration, engines |
| **worker** | Celery 5 on Redis | — | Executes scans asynchronously |
| **scanner-source** | Go 1.26 + Semgrep OSS | 8080 (private) | Source code AST + data-flow scanning |
| **scanner-container** | Go 1.26 + Syft + `crypto/x509` | 8080 (private) | Image SBOM, certs, public keys |
| **scanner-cloud-hsm** | Go 1.26 + PKCS#11 / AWS KMS | 8080 (private) | Key-object metadata |
| **postgres** | PostgreSQL 16 | 5433→5432 | Inventory, assessment history |
| **redis** | Redis 7 | 6379 | Celery broker, sessions, progress pub/sub |

> **Why 5433 on the host:** the development machine already runs a native
> `postgresql-x64-16` service on 5432. Binding over it would silently route the
> app at the wrong database. The container still listens on 5432 internally.

### Redis carries three unrelated workloads

1. **Celery broker + result backend** — job queue, `visibility_timeout` set to
   twice the scan timeout so a long scan is never redelivered mid-flight.
2. **Session store** — opaque session IDs → `{user_id, username, role, csrf_token}`,
   with a TTL. The cookie itself carries no authorization data.
3. **Progress pub/sub** — channel `trinetra:scan:{scan_id}`. The worker publishes;
   whichever API process holds the browser's WebSocket subscribes and relays.

Pub/sub rather than in-process callbacks because the worker and the API are
**separate processes** — an in-process callback would never reach the browser.

---

## 5. The end-to-end request lifecycle

```
 TARGET            repository · container image · HSM export · KMS
    │
    ▼
┌──────────────────────────────────────────────────────────────────┐
│ STAGE 1  DISPATCH                          api/scans.py          │
│   POST /api/scans  (Idempotency-Key header)                      │
│   RBAC: Admin|Analyst · CSRF verified                            │
│   → row in `scans`, status = queued                              │
│   → Celery task enqueued, task_id = scan-{scan_id}               │
│   Payload is small, secret-free, and idempotent by construction. │
└──────────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────────┐
│ STAGE 2  PREPARE TARGET              services/scan_orchestrator  │
│   git URL  → shallow clone (--depth 1) into scan-workdir         │
│   local    → resolved, must stay inside scan-workdir root        │
│   → returns a path RELATIVE to the scanner's shared input root   │
└──────────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────────┐
│ STAGE 3  SCAN                        (inside the scanner service)│
│   POST /internal/v1/scan  { scan_id, target_reference }          │
│   Bearer token verified by SHA-256 constant-time compare         │
│   targetpath.Resolve rejects any traversal outside the root      │
│   Semgrep / Syft / PKCS#11 parser runs                           │
└──────────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────────┐
│ STAGE 4  CBOM ASSEMBLY                    scanners/cbom-go       │
│   every scanner reduces its output to one shape: cbom.Finding    │
│   sorted → deduped → validated against the frozen schema         │
│   → artifact-store/cbom/{scan_id}.json   (IMMUTABLE)             │
│   Deterministic: same input ⇒ byte-identical document            │
└──────────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────────┐
│ STAGE 5  INGEST                      services/cbom_ingest.py     │
│   validated AGAIN in Python (defence in depth)                   │
│   CycloneDX component → `artefacts` row                          │
│   purpose + algorithm normalised through vocab.py                │
│   trinetra:data-category property lifted out as scanner evidence │
│   whole component preserved verbatim in raw_cbom JSONB           │
└──────────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────────┐
│ STAGE 6  CONTEXT                  services/artefact_context.py   │
│   user → scanner evidence → org preset → unknown                 │
│   each field records WHICH tier supplied it                      │
│   → ArtefactContext + provenance map                             │
└──────────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────────┐
│ STAGE 7  RISK          two independent tracks, then combination  │
│   mosca_engine     X + Y vs Z                                    │
│   resource_engine  first t where P(t) ≥ Q                        │
│   final_risk_engine  additive 100-point score → P0 | P1 | P2     │
│   → APPEND a new risk_assessments row                            │
└──────────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────────┐
│ STAGE 8  RECOMMENDATION       (actionable findings only: P0/P1)  │
│   ML-KEM · ML-DSA · SLH-DSA · AES-256, with parameter set        │
│   gated by required security category, with cited FIPS sources   │
└──────────────────────────────────────────────────────────────────┘
    │
    ▼
 DASHBOARD  ·  CBOM export  ·  PDF report
```

### Live progress

Every stage transition is published to Redis and streamed to the browser over
`WS /ws/scans/{scan_id}`.

```
queued  →  running  →  completed
                   ↘   failed  (always with an actionable message + error_code)
```

A scanner crash **always** lands on `failed`. A scan never hangs at `running`
forever — that is enforced by the worker's `except` clauses, not by hope.

Progress publishing is **best-effort by design**: `progress.publish` never
raises. A dead Redis must not fail a scan that is otherwise working. The user
loses live progress, not their results.

### Redelivery is safe

If the worker retries after the scanner already published its CBOM,
`execute_scan` checks for `artifact-store/cbom/{scan_id}.json` and **resumes at
ingest** rather than asking the scanner to overwrite an immutable file. A second
check on `count_artefacts_for_scan` prevents double-insertion.

---

## 6. Discovery layer — the three scanners

| Scanner | Engine | Detects | Asset types emitted |
|---|---|---|---|
| **source** | Semgrep OSS (43 crypto rules, 7 languages) | RSA, ECC, DH, DSA, AES, MD5/SHA-1/SHA-256, OpenSSL C API, Java JCA | `algorithm` |
| **container** | Syft + Go `crypto/x509` | crypto libraries by version; certificates and public keys inside the image | `library`, `key`, `certificate` |
| **cloud-hsm** | PKCS#11 metadata parser, AWS KMS | key objects, their type and capabilities | `hardware`, `cloud_service` |

Languages parsed by the source scanner: **Python, Go, JavaScript, TypeScript,
C, C++, Java**.

### Two rules govern every Semgrep rule, and both are load-bearing

1. **Match call expressions, never bare identifiers.** A rule matching the token
   `rsa` would flag `rsa = "some string"`. The rule must match `RSA.generate(...)`.
2. **Interpolate captured values into the message.** Semgrep OSS emits no
   `metavars` field, so the message string is the **only** channel that can carry
   a key size back to the scanner. `crypto-rules.yml`
   depends on this.

### Data-classification rules — how X gets evidence

`data-classification-rules.yml`
runs Semgrep in **taint mode**:

```
 sources: aadhaar_number, card_number, medical_record_id, …
 sinks:   .encrypt()  .update()  .doFinal()  .Seal()  .sign()
```

When a source reaches a sink, the scanner attaches a
`trinetra:data-category` property to that component. This is *evidence of what
the code protects*, not a business decision — so it enters the context chain
below a user's confirmation, never above it.

### Shared Go module: `cbom-go`

All three scanners import one internal module through a Go workspace
(`scanners/go.work`):

| Package | Responsibility |
|---|---|
| `cbom` (root) | `Finding` → CycloneDX 1.6 `Document`; sorting, dedup, determinism |
| `validate.go` | JSON-Schema validation before write |
| `vocab.go` | canonical → CycloneDX purpose translation (inverse of `vocab.py`) |
| `scannerapi` | the shared HTTP boundary: auth, 1 MiB body cap, UUID validation, graceful shutdown |
| `targetpath` | `Resolve` — rejects any path escaping the input root |
| `artifactstore` | atomic, immutable writes into the shared volume |

One HTTP contract, implemented once:

```http
POST /internal/v1/scan
Authorization: Bearer <≥32 chars>
Content-Type: application/json

{ "scan_id": "<uuid>", "target_reference": "<relative path or image ref>" }

→ 200 { "scan_id", "status": "completed", "artifact_reference",
        "finding_count", "scanner_version" }
→ 4xx/5xx { "code", "message" }     ← safe, non-leaking messages only
```

The backend validates this response with a Pydantic model set to
`extra="forbid"`, and re-checks that `scan_id` matches and `status == "completed"`.
A mismatched result is rejected, not trusted.

---

## 7. Upstream tooling — what Trinetra builds on

Trinetra does not write its own parser, its own SBOM generator, or its own
quantum resource estimator. Each of those is a mature open-source project, and
reimplementing one would be both worse and unciteable. Trinetra's contribution is
the **integration and the judgement layer**: taking heterogeneous evidence from
several proven tools, reducing it to one inventory, and scoring it against
versioned, sourced policy.

### 7.1 The integration rule

> **Every upstream tool is a source of evidence, never a source of verdicts.**

A tool tells Trinetra *what is there*. Trinetra decides *what it means*. This is
principle P1 applied to third-party code, and it has three practical
consequences:

1. **Wrap, never fork.** Each tool runs as a subprocess or a library call behind a
   thin adapter that reduces its output to `Finding`. When the tool updates, the
   adapter changes; nothing else does.
2. **The adapter is the trust boundary.** Tool output is parsed and validated, not
   trusted. A malformed Semgrep result is a scanner error, not a crash.
3. **Never let a tool's vocabulary leak inward.** Syft calls things `artifacts`,
   Semgrep calls them `results`, Presidio calls them `entities`. All three become
   `Finding` at the adapter, in Trinetra's canonical snake_case vocabulary (P6).

### 7.2 Licence discipline

Trinetra is deployed on-premise inside government and defence networks. Two rules
follow, and they are procurement requirements, not preferences:

- **Prefer permissive licences** (Apache-2.0, MIT, BSD) for anything linked or
  redistributed. A copyleft dependency invoked as a separate process is usually
  acceptable; one linked into the binary may not be.
- **Prefer tools that run fully offline.** Anything requiring a cloud account, a
  login, or a callback to a vendor service is disqualified for the core path,
  regardless of quality. This is why the source scanner uses **Semgrep OSS**
  rather than the hosted product, and why the resource estimator runs
  **offline**, generating profiles ahead of time rather than calling a service at
  scan time.

Record each tool's licence and version in the CBOM `metadata.tools` block. A
CBOM that cannot say which version of which tool produced it is not an audit
artefact.

---

### 7.3 The core stack

Six tools carry the primary pipeline. These are the ones to build first.

| Tool | Stage | What Trinetra takes from it | What Trinetra does not take |
|---|---|---|---|
| **Semgrep OSS** | Discover | Crypto API call sites with file + line; taint paths from PII source to crypto sink | Severity ratings — Trinetra scores, Semgrep does not |
| **Tree-sitter** | Discover | Precise AST for key-size resolution Semgrep cannot express | Any judgement about the code |
| **Syft** | Discover | Package inventory from images and filesystems, with versions | Vulnerability claims — that is OSV's job, and neither is a crypto verdict |
| **CycloneDX 1.6** | Contract | The CBOM schema and `cryptographic-asset` component model | — (it is a format, not a tool) |
| **Microsoft QDK / Resource Estimator** | Assess | Q: logical qubits and gate counts for a modelled attack, with assumptions | The break year — that comes from crossing Q against P(t) |
| **liboqs (Open Quantum Safe)** | Recommend | PQC parameter sets and object sizes for ML-KEM / ML-DSA / SLH-DSA | The recommendation itself, which is policy-gated by security category |

#### Semgrep — pattern discovery

**Role:** the primary source-code detector. Runs as a subprocess against a rule
pack; results are parsed into findings.

Two constraints, both load-bearing and both already documented in section 6:

- Rules must match **call expressions, never bare identifiers**.
- Rules must **interpolate captured values into the message**, because Semgrep OSS
  emits no `metavars` field — the message is the only channel that can carry a key
  size back to the scanner.

**Taint mode** is what gives the Mosca track its scanner-evidence tier: sources
are PII patterns, sinks are crypto calls, and a reaching path attaches a
`data-category` property to the finding.

> **Design note.** The message-interpolation constraint is a workaround for an OSS
> limitation, and it is brittle — a rule author who forgets it silently loses the
> key size, and the finding degrades to `NEEDS_CONTEXT`. Tree-sitter exists in
> this stack primarily to remove that fragility.

#### Tree-sitter — structural precision

**Role:** AST parsing where a pattern match is not enough.

Semgrep finds *that* `RSA.generate(...)` was called. Tree-sitter answers questions
a pattern cannot: what is the key size when it arrives through a constant, a
config lookup, or a variable assigned three lines earlier? Is this call inside
dead code or a test fixture?

Use it as a **second pass on sites Semgrep already found**, not as a primary
scanner. Parsing every file with both tools doubles the work for no gain; parsing
only the files with hits is cheap.

This is also the honest answer to the `AES.new(key, MODE_GCM)` problem in section
21. Trinetra currently reports `NEEDS_CONTEXT` because the call does not state
128 or 256. A Tree-sitter pass that resolves `key` to its assignment can often
answer it — and when it cannot, `NEEDS_CONTEXT` remains correct rather than
becoming a guess.

#### Syft — component inventory

**Role:** SBOM generation from container images and filesystems.

Syft produces a package list. Trinetra filters it against a curated
crypto-library set and emits `library` artefacts.

**The critical discipline:** a library finding is **dependency evidence, not an
algorithm**. OpenSSL being installed proves a crypto implementation exists, not
that any particular algorithm is used. This is why the `algorithm` column is left
empty for `library` artefacts and why they are never scored — the rule is stated
in sections 9 and 21 and it exists precisely because Syft makes it so easy to
violate.

Syft can emit CycloneDX directly. **Do not use that path as the CBOM.** Syft's
CycloneDX describes software components; Trinetra's describes cryptographic
assets. Take Syft's native JSON, map it through the adapter, and let the CBOM
builder produce the document — one writer, one shape, one schema.

#### CycloneDX — the contract

**Role:** the interchange format, and the reason Trinetra's output is portable.

CycloneDX 1.6 defines `cryptographic-asset` components with `cryptoProperties`.
This is not a Trinetra invention — it is the OWASP standard for exactly this
purpose, which is what makes a Trinetra CBOM consumable by other tools.

Trinetra extends it only through namespaced `properties`
(`trinetra:key-size-bits`, `trinetra:data-category`). Namespacing matters: a
consumer that does not know Trinetra ignores them safely, and the document stays
schema-valid.

#### Microsoft QDK / Resource Estimator — Q

**Role:** produces the attack-resource threshold Q for an algorithm and key size.

**Run it offline, ahead of time.** The estimator is a development-time tool that
generates the capability profile; it is not in the scan path. A scan must not
depend on a quantum toolchain being installed, and the resulting profile must be
a versioned, reviewable, citable artefact — which a runtime computation is not.

The generator produces, for each algorithm and key size: logical qubit count,
logical gate count (Toffoli or T), the construction cited, and **the assumptions
block** — error-correction scheme, logical-qubit definition, physical error rate,
caveats.

That last part is not optional. Section 10's discipline — *"a Q without its
assumptions is a number nobody can check"* — is enforced here, at generation
time. A profile entry without an assumptions block should fail validation on
load.

#### liboqs — PQC parameters

**Role:** the authoritative source for ML-KEM, ML-DSA and SLH-DSA parameter sets
and their object sizes.

Used to build the algorithm profile: public key, ciphertext and signature sizes
per parameter set, cited to FIPS 203/204/205.

**What it must not be used for:** manufacturing a fit score. Section 11 is
explicit that no composite confidence is published, because *"a universal
deployment score cannot be derived from a standard's object sizes."* liboqs gives
you the sizes. It cannot tell you whether an 1,184-byte key breaks a protocol's
MTU on someone's network — so the profile records the size as fact and labels the
operational dimensions as unmeasured.

Optionally, liboqs also allows **benchmarking on the deployment's own hardware**
— which converts an unmeasured dimension into a measured one. That is the correct
way to obtain a latency number: measure it, do not model it.

---

### 7.4 Coverage extensions

Four tools that widen what Trinetra can see. Each closes a real gap, and each is
genuinely optional for a first build.

| Tool | Closes the gap | Adds |
|---|---|---|
| **testssl.sh** | Deployed TLS ≠ configured TLS | Protocol versions, cipher suites, cert key types on a live endpoint |
| **Ghidra** | Compiled binaries are opaque to source scanning | Crypto constants and API calls in stripped binaries |
| **OSV-Scanner** | A vulnerable crypto library is a present-tense risk | CVE data per package, alongside the quantum verdict |
| **Presidio** | PII detection by regex is weak | NER-based sensitive-data classification for the X evidence tier |

#### testssl.sh — observed versus declared

This is the **highest-value extension**, because it answers a question no other
scanner in the stack can: what is *actually negotiated* on a live port.

Source code says what a service intends. A container image says what is
installed. Neither tells you that a load balancer in front of it still accepts
TLS 1.0, or that the certificate is RSA-2048 regardless of what the application
configures.

Architecturally this is **a fourth scanner service**, not an addition to an
existing one, for the reason in section 3: it needs outbound network access to
reach live endpoints, and that is a different blast radius. It belongs on
`scanner-egress`, isolated from the source tree.

Findings map to `protocol` and `certificate` asset types and score through the
same engines — a TLS 1.0 endpoint short-circuits on current security policy
exactly as MD5 does.

#### Ghidra — binaries

Firmware, vendor appliances, and legacy services ship as binaries with no source.
For critical infrastructure — which is Trinetra's stated user — this is a real
and common case.

Ghidra runs **headless** against a binary and yields crypto constants (S-boxes,
known primes, curve parameters) and imported crypto API calls.

Two honest limits, and both must reach the UI:

- **Evidence strength is lower.** A detected AES S-box proves AES is present in
  the binary, not that it is reachable or used. This is closer to library evidence
  than to a call site.
- **It is slow.** Headless analysis of a large binary takes minutes to hours, not
  seconds. This breaks the interactive scan model and needs its own queue and its
  own progress semantics.

Given both, this is genuinely post-MVP.

#### OSV-Scanner — present-tense risk

Trinetra scores a *future* risk: when will this become breakable? OSV answers a
*current* one: is this library exploitable today?

An OpenSSL version with a known CVE deserves attention now, independent of any
quantum timeline. Attaching that to the `library` artefact makes the finding
actionable in a way a never-scored dependency record is not.

**Keep the two verdicts separate.** Do not fold a CVE into the quantum risk
score. They answer different questions on different timelines, and the additive
100-point model in section 10 has no factor for present-day exploitability — nor
should it. Present it as a parallel fact on the same artefact.

#### Presidio — stronger X evidence

Semgrep's taint rules catch PII by pattern: variables named `aadhaar_number`,
`card_number`. That works when code is well-named and fails when it is not.

Presidio adds NER-based detection — it recognises that a field *contains* an
Aadhaar number even when it is called `user_field_3`.

Two integration constraints:

- **It still only supplies `data_category`.** Section 9 narrows the
  `scanner_evidence` tier in code to that one field, deliberately, so that a
  future scanner cannot become a channel for facts no scanner can know. Presidio
  is exactly the "future scanner" that rule anticipates.
- **Confidence must survive the boundary.** Presidio returns a score. A
  low-confidence NER hit is weaker evidence than a variable literally named
  `aadhaar_number`, and the evidence list must say so rather than flattening both
  to `scanner_dataflow`.

---

### 7.5 Research reference

**fault-tolerance-economics** — a published resource and cost model for
fault-tolerant quantum computing, including a Shor/RSA-2048 physical-qubit
estimate with explicit hardware assumptions and sensitivity analysis.

Not a dependency. Its value is as a **cross-check and a template**: it models the
same quantity the QDK generator produces, from different assumptions. If two
independent models disagree by an order of magnitude, that disagreement is itself
information the capability profile should record.

Its sensitivity analysis is also the right model for how the scenario multipliers
(`conservative 0.5× / baseline 1× / aggressive 2×`) should eventually be
justified — currently they are round numbers, and a sourced sensitivity range
would be stronger.

---

### 7.6 What each tool must not become

| Tool | The failure mode |
|---|---|
| Semgrep | Letting its `severity` field become a priority. Trinetra scores; Semgrep does not know the business context |
| Tree-sitter | Building a second detection engine in parallel. It refines findings Semgrep already produced |
| Syft | Emitting its CycloneDX as the CBOM. Two writers, two shapes, drift |
| QDK | Running at scan time. Q is generated offline into a versioned profile, or it is not citable |
| liboqs | Producing a composite fit score. It supplies sizes; operational dimensions stay labelled unmeasured |
| OSV | Folding CVE severity into the quantum score. Different questions, different timelines |
| Presidio | Supplying anything except `data_category`. The tier is narrowed in code for exactly this reason |
| testssl.sh | Running on the internal scanner network. It needs egress, so it is isolated like the container scanner |
| Ghidra | Being presented as equal-strength evidence. A constant in a binary is not a reachable call site |

---

### 7.7 Build order

Ordered by dependency and by how much each unlocks.

| Phase | Add | Unlocks |
|---|---|---|
| **1** | CycloneDX schema + the `Finding` shape | The contract everything else writes into. Nothing works before this |
| **2** | Semgrep + rule pack | Source findings — the primary evidence stream |
| **3** | QDK generator (offline) → capability profile | Track B. The risk engine cannot run without Q |
| **4** | liboqs → algorithm profile | Recommendations |
| **5** | Syft | Container coverage, `library` artefacts |
| **6** | Tree-sitter second pass | Key sizes Semgrep cannot resolve; fewer `NEEDS_CONTEXT` |
| **7** | Presidio | Stronger X evidence |
| **8** | testssl.sh (new scanner service) | Observed versus declared crypto — the widest coverage gain |
| **9** | OSV-Scanner | Present-tense risk alongside future risk |
| **10** | Ghidra (own queue) | Binary coverage |

**Phases 1–4 are the minimum viable platform.** They produce a scored, cited,
recommendation-bearing CBOM from source code. Everything after that widens
coverage without changing the architecture — which is the test of whether the
architecture is right.

---

## 8. The CBOM contract

`cbom.schema.json` is the frozen contract
between Go and Python. It is validated **twice** — once in Go before the file is
written, once in Python on ingest. Defence in depth: a schema drift on either
side is caught at the boundary, not three layers deep.

```jsonc
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:…",
  "version": 1,
  "metadata": {
    "timestamp": "…",
    "tools": [{ "vendor": "Trinetra", "name": "source-scanner", "version": "…" }],
    "component": { "type": "application", "name": "<target>" }
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "bom-ref": "…",
      "name": "RSA-2048",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "pke",
          "parameterSetIdentifier": "2048",
          "purpose": ["keyEncapsulation"]
        }
      },
      "evidence": {
        "occurrences": [
          { "location": "svc/auth.py", "line": 20, "additionalContext": "…" }
        ]
      },
      "properties": [
        { "name": "trinetra:key-size-bits",  "value": "2048" },
        { "name": "trinetra:data-category",  "value": "aadhaar_pii" }
      ]
    }
  ]
}
```

### The unified finding

Whatever produced it, every finding becomes one `cbom.Finding` and leaves as a
CycloneDX 1.6 `cryptographic-asset`. **This is the moment three different
inspection methods become one inventory.** Nothing downstream can tell — or needs
to — which of the three found a given asset.

Components that are not `cryptographic-asset` are legitimately present in a CBOM
and are simply skipped on ingest. A document with zero components is a **valid
result** — a repository genuinely free of cryptography — and yields an empty
list, not an error.

---

## 9. Ingest and the context chain

### CycloneDX → `artefacts` column mapping

| CBOM path | Column | Note |
|---|---|---|
| `cryptoProperties.assetType` | `type` | defaults to `algorithm` rather than failing |
| `name` | `name` | e.g. `RSA-2048` |
| `name` normalised | `algorithm` | **empty for `library`** — see below |
| `properties[trinetra:key-size-bits]` → else `parameterSetIdentifier` | `key_size_bits` | |
| `algorithmProperties.parameterSetIdentifier` | `size_or_version` | |
| `algorithmProperties.purpose[]` | `purpose` | via `normalise_purpose` |
| `evidence.occurrences[0]` | `location` | rendered `"file.py, line 42"` |
| `evidence.occurrences[0].additionalContext` | `used_for` | |
| *(whole component)* | `raw_cbom` JSONB | nothing from the scanner is ever lost |
| `properties[trinetra:data-category]` | `observed_data_category` | scanner evidence |

> **Why `algorithm` is empty for libraries:** a package name such as *OpenSSL* is
> real dependency evidence, but it is not an algorithm. Keeping the column empty
> prevents the risk engine from manufacturing an attack model out of a library
> name. OpenSSL being installed proves a crypto implementation exists, not that
> any particular algorithm is used.

### The context chain

No scanner can know how long the data it found must stay secret, or whether the
service is a payment gateway or a toy script. `RSA.generate(2048)` looks
identical in both. So business context is resolved through a strict precedence
chain, and **every field records which tier supplied it**:

```
 crypto finding
      │
      ├── 1. user confirmation ───────────┐  strongest
      ├── 2. scanner data-flow evidence ──┤
      ├── 3. organisation preset ─────────┤
      └── 4. unknown ─────────────────────┘  weakest
                  │
                  ▼
        ArtefactContext + provenance{field → tier}
```

Two hard rules enforced in `resolve_context`:

- **A file path is never business context.** The location is explicitly discarded
  before resolving criticality or retention.
- **The `scanner_evidence` tier is narrowed in code to `data_category` alone**, so
  a future scanner cannot become a back-channel for facts no scanner can know.

---

## 10. The risk engine — two tracks

### Track A — Mosca / data lifetime

> **Question:** will migration finish before the data stops being safe?

```
        X + Y > Z   →  already too late
```

| Symbol | Meaning | Source |
|---|---|---|
| **X** | confidentiality lifetime | aggregated ranked evidence |
| **Y** | migration time | user or organisation — **never inferred** |
| **Z** | threat horizon | configured planning horizon, else `M` from Track B |

#### Resolving X

Evidence is collected from four sources, ranked:

| Source constant | Trust on its own |
|---|---|
| `EVIDENCE_USER` | high |
| `EVIDENCE_SCANNER` (data-flow) | medium |
| `EVIDENCE_ORG_POLICY` | high |
| `EVIDENCE_LEGAL_PROFILE` | low |

Precedence is strict. **Within the strongest tier that produced anything, the
longest lifetime governs** — if an artefact protects both session tokens and
health records, the health record decides.

The retention profile
(`retention-policy-2026.1.json`)
covers 10 categories and carries a deliberate warning printed in the document
itself:

> **Indian statutes mandate retention *minimums*, not confidentiality lifetimes.**

Every entry declares its basis as `legal`, `regulatory_minimum`, or `assumption`,
and cites a source. `biometric` (30y) and `credential_secret` (5y) are explicitly
labelled Trinetra planning assumptions with no statute behind them.

**When no evidence supports an X, Trinetra reports none.** It does not default.

`Z` records its own basis: `org_horizon`, `resource_model`, or `unavailable`.

### Track B — quantum resource

> **Question:** under stated hardware assumptions, when could this specific
> algorithm become attack-feasible?

```
 algorithm + key size
      │
      ▼
 Q = logical resources the attack requires
      │   RSA      → Gidney–Ekerå 2021 formulas
      │   ECC-256  → Google 2026 calibrated estimate
      │   ECC-n    → Roetteler 2017 conservative formulas
      ▼
 P(t) = projected capability per year, 2026–2045
      │   IBM roadmap anchors → interpolated → extrapolated tail
      │   scaled by scenario: conservative 0.5× · baseline 1× · aggressive 2×
      ▼
 first t where  P(t) ≥ Q       ← BOTH dimensions must be met
      ▼
 M = years until that year     → offered to Track A as Z_resource
```

Three disciplines make this defensible:

1. **Q always carries its assumptions.** Error-correction scheme, logical-qubit
   definition, physical error rate, and explicit caveats travel with every Q, all
   the way into the UI.
2. **A year qualifies only when both dimensions are met.** Several curve years
   publish a gate count but no comparable logical-qubit count. Those years cannot
   satisfy a threshold — half an answer is not an answer.
3. **A scenario scales P(t), never Q.** The attack requirement is a property of
   the algorithm, not of anyone's roadmap optimism.

Status values: `calculated`, `beyond_horizon`, `model_unavailable`, `not_required`.
Curve-point confidence maps `roadmap|moderate → medium`, `low → low`.

### Combination — the final risk engine

The tracks are combined **additively**, not averaged, because they are
independent evidence about different things.

```
Final Risk =
    algorithm quantum vulnerability   25
  + Mosca timing risk                 20      ← Track A
  + resource feasibility              15      ← Track B
  + data sensitivity                  12
  + business criticality              10
  + exposure                          10
  + migration complexity               8
  ─────────────────────────────────────
                                     100
```

Bands: **≥75 → P0** · **50–74 → P1** · **<50 → P2**

#### Three rules that keep the number honest

1. **Policy short-circuits run first.** An already-broken algorithm (MD5, SHA-1,
   DES, 3DES), a known quantum-resistant one, or a dependency-only finding is
   decided by policy and returns **no score**. Scoring them would imply a
   measurement that was never made.
2. **A factor with no evidence contributes zero and says so** — never a midpoint.
3. **The score is `None` unless both tracks produced a result.** Half the evidence
   still makes a number; it just is not a *comparable* one.

#### Confidence

The weaker of the two tracks' confidences, dropped one level further when any
factor lacked evidence. A crossing year in the **extrapolated tail** of the
capability curve is low confidence *by construction*, because the curve itself
says so.

#### Worked example — real engine output

```
Algorithm: RSA-2048          location: patient.py, line 20

Track A   X = 8   (aadhaar_pii, proved by scanner data-flow)
          Y = 4   (user-confirmed)
          Z = 12  (configured planning horizon)
          8 + 4 vs 12  →  not urgent, exactly 0 years of headroom

Track B   Q = 6,190 logical qubits / 2,624,225,018 logical gates
          P(t) ≥ Q first met in 2036  →  M = 10 years   [baseline]

Combined  algorithm quantum vulnerability   25/25
          mosca timing risk                  0/20   ← no shortfall
          resource feasibility               8/15
          data sensitivity                   4/12
          business criticality              10/10
          exposure                           7/10
          migration complexity               4/8
          ────────────────────────────────────────
                                            58/100   confidence: low
          → P1 — fix this quarter
```

Note what this shows. The Mosca track contributes **zero** — migration finishes
exactly on the horizon, so there is no timing shortfall to score. The P1 comes
from the algorithm being Shor-breakable, a crossing 10 years out, and confirmed
high criticality. Confidence is `low` because 2036 sits in the extrapolated tail
of the curve. **Neither number is talked up.**

---

## 11. The recommendation engine

Runs only on **actionable** findings (P0 / P1). Profile-driven and pure.

| Current | Purpose | Recommended | Parameter sets by security category |
|---|---|---|---|
| RSA, ECC, ECDH, DH, X25519 | key exchange | **ML-KEM** (FIPS 203) | 1 → 512, 3 → 768, 5 → 1024 |
| RSA, ECC, ECDSA, DSA, Ed25519 | signature | **ML-DSA** (FIPS 204) | 1 → 44, 3 → 65, 5 → 87 |
| … where statelessness is required | signature | **SLH-DSA** (FIPS 205) | SHA2-128s / 192s / 256s |
| AES-128 | encryption | **AES-256** | direct |

Hybrid mode pairs the PQC algorithm with a classical partner
(`DEFAULT_CLASSICAL_PARTNER = X25519`) when the context calls for it.

### Deliberately, there is no single confidence score

`FitResult.total` is **null by design** in evidence profiles:

> A universal deployment score cannot be derived from a standard's object sizes.

A composite number would blur what is published fact (FIPS parameter sizes) and
what your team still has to test (latency on your hardware, protocol
compatibility). So unmeasured dimensions are **labelled as unmeasured** rather
than scored. `fit_score` is nullable in the database for exactly this reason —
an unknown algorithm escalates to `MANUAL_REVIEW` rather than silently scoring
100.

The interface is therefore required to show the current versus recommended
algorithm side by side with published FIPS sizes and cited sources, and to label
unmeasured dimensions as unmeasured rather than scoring them (section 15, S6).

---

## 12. Data model

```
users
  │
  ├──requested_by──▶ scans ──┬── artefacts ──┬── artefact_contexts  (current, editable)
  │                          │               │
  │                          │               └── risk_assessments   (APPEND-ONLY)
  │                          │                        │
  │                          │                        └── recommendations  (0..1)
  │                          └── reports
  │
  └──created_by──▶ org_setting_versions   (immutable; exactly one active)
```

| Table | Cardinality | Nature |
|---|---|---|
| `users` | — | Provisioned, single-tenant. Password hashes never selected into response models |
| `scans` | 1 target run | Re-scanning creates a **new row**; nothing is overwritten |
| `artefacts` | N per scan | One cryptographic asset. `raw_cbom` JSONB keeps the original entry |
| `artefact_contexts` | 0..1 per artefact | Current business context + field-level `provenance_json` |
| `risk_assessments` | N per artefact | **Append-only.** `artefact.risk_assessment` returns the newest |
| `recommendations` | 0..1 per assessment | Unique FK — one recommendation per verdict |
| `org_setting_versions` | N, one `is_active` | Immutable config versions |
| `reports` | N per scan | Generated CBOM / PDF references |
| `org_settings` | 1 row | Legacy singleton |

### Why relational, with a JSONB pocket

An artefact belongs to one scan, has one current context and an append-only
assessment history. Each assessment has at most one recommendation. That is a
textbook relational model at moderate scale. Where the shape really *is* variable
— the original CBOM entry — a JSONB column gives NoSQL flexibility without giving
up integrity.

### What a `risk_assessments` row stores

Both tracks in full, so any verdict can be re-derived and audited:

```
 Mosca track      mosca_x_years, mosca_y_years, mosca_z_years, mosca_z_basis,
                  mosca_is_urgent, mosca_shortfall_years, mosca_evidence_json

 Resource track   resource_m_years, resource_scenario, resource_assumptions_json,
                  attack_threshold_json, forecast_capability_json,
                  projected_break_year, migration_deadline_year,
                  quantum_projection_status

 Combined         final_score, final_confidence, score_contributions_json,
                  weights_version, priority, rationale,
                  missing_fields_json, input_provenance_json

 Versions         policy_version, quantum_forecast_profile_version, weights_version
```

> **Three legacy columns are deliberately left untouched.**
> `data_lifetime_years`, `migration_time_years` and `quantum_arrival_years` were
> written when X and Z briefly meant something else. Rewriting them would falsify
> history. The live values are in the `mosca_*` columns.

### Indexes

```
users                 ix_users_username
scans                 ix_scans_requested_by
                      uq_scans_requester_idempotency   (requested_by, idempotency_key) UNIQUE
artefacts             ix_artefacts_scan_id, ix_artefacts_name
risk_assessments      ix_risk_assessments_priority
reports               ix_reports_scan_id
                      uq_reports_requester_idempotency  UNIQUE
org_setting_versions  ix_org_setting_versions_active
```

The two unique idempotency indexes are what make `Idempotency-Key` a real
database-level guarantee rather than an application-level hope.

### Repository layer

`backend/app/repositories/__init__.py` is
**the only code that touches the database**. ~30 functions, all taking an
explicit `Session`. Routers and engines never write SQL. This keeps engines pure
(P2) and makes the data access surface auditable in one file.

### Migrations

| Revision | Introduces |
|---|---|
| `0001_initial_schema` | scans, artefacts, assessments, recommendations, settings |
| `0002_add_users` | users, RBAC |
| `0003_platform_contract` | idempotency, artifact references, error codes |
| `0004_engine_contract` | provenance, missing-fields, policy versions |
| `0005_quantum_capability_forecast` | attack thresholds, capability curve columns |
| `0006_risk_assessment_state` | projection status, assessment basis |
| `0007_recommendation_evidence` | fit breakdown, profile provenance |
| `0008_two_track_risk` | `mosca_*`, `resource_*`, `final_score`, contributions |

---

## 13. Versioned policy profiles

Every judgement Trinetra makes is traceable to a versioned JSON profile, and
every profile cites its sources. Profiles live in
`backend/app/engines/profiles/` and are loaded
through a `@cache`d, **validating** loader — a malformed profile fails at load,
not at scoring time.

| Profile version | Supplies | Validation on load |
|---|---|---|
| `retention-policy-2026.1` | X — confidentiality lifetimes, with legal basis | categories + sources required |
| `quantum-capability-2026.2` | P(t) curve, attack models, scenarios | curve + scenarios required |
| `risk-weights-2026.1` | factor weights and score bands | weights must total the band max |
| `current-security-2026.1` | already-broken algorithms (NIST SP 800-131A) | — |
| `nist-pqc-evidence-2026.2` | PQC replacements (FIPS 203/204/205) | `selection_policy.required_security_category` |

Two schema versions coexist in the algorithm profile loader:

- **schema v1** (`2026.1`) — five weighted fit dimensions summing to exactly 1.0,
  validated to within `1e-9`.
- **schema v2** (`2026.2`) — evidence-based; requires a named `selection_policy`
  and drops the composite score entirely.

Older version strings (`builtin-0.1.0`, `quantum-capability-2026.1`,
`nist-pqc-fit-2026.1`) are retained purely for **read compatibility** with
settings rows written before the newer profiles existed. New assessments always
use the active settings row.

### Changing a profile re-scores everything

`POST /api/settings/risk-presets` →

1. creates a **new immutable** `org_setting_versions` row and deactivates the old,
2. calls `rescore_all`, which rebuilds each artefact's context from stored
   provenance and re-runs `classify_risk` + `recommend_replacement`,
3. **appends** a new assessment per artefact (history preserved),
4. returns `artefacts_rescored`.

Because the engines are pure (P2) and X, Y and Z were stored, this is a genuine
recalculation, not a relabel. It is also the most demoable moment in the product:
move the horizon slider, watch every verdict honestly change.

---

## 14. API surface

Enumerated from the running routers. Interactive docs at `/docs` (Swagger) and
`/redoc`.

### Scans

```
POST    /api/scans                       create   [Admin|Analyst] Idempotency-Key, CSRF
GET     /api/scans                       history, paginated
GET     /api/scans/capabilities          which scanners are enabled
GET     /api/scans/{scan_id}             one scan
GET     /api/scans/{scan_id}/artefacts   findings + risk + recommendation joined
DELETE  /api/scans/{scan_id}             remove scan and all dependents  [Admin] CSRF
WS      /ws/scans/{scan_id}              live progress stream
```

### Artefacts

```
GET     /api/artefacts/{artefact_id}          detail + raw CBOM + assessment history
PATCH   /api/artefacts/{artefact_id}/context  correct context → APPENDS a new assessment
```

### Dashboard & settings

```
GET     /api/dashboard/summary           counts, priority breakdown, worst offenders
GET     /api/settings/risk-presets       horizon, scenario, curve, cited sources
POST    /api/settings/risk-presets       change → re-scores every artefact  [Admin]
```

### Reports

```
POST    /api/scans/{scan_id}/reports     generate (cyclonedx-json | pdf), Idempotency-Key
GET     /api/reports/{report_id}         download
```

### Auth & admin

```
POST    /api/auth/login                  → sets HttpOnly cookie, returns CSRF token
POST    /api/auth/logout
GET     /api/auth/me
GET     /api/auth/session                restore after reload
GET     /api/admin/users                 list        [Admin]
POST    /api/admin/users                 provision   [Admin]
PATCH   /api/admin/users/{user_id}       role / active state  [Admin]
```

### Ops

```
GET     /health                          liveness — every service exposes one
```

### Uniform error contract

Three exception handlers in `main.py` guarantee every
failure is JSON with a **stable machine-readable code**:

```jsonc
{ "code": "NOT_FOUND",        "message": "…" }                    // HTTPException
{ "code": "VALIDATION_ERROR", "message": "…", "details": [ … ] }   // 422
{ "code": "INTERNAL_ERROR",   "message": "…" }                     // 500
```

| HTTP | Code |
|---|---|
| 400 | `INVALID_REQUEST` |
| 401 | `UNAUTHENTICATED` |
| 403 | `FORBIDDEN` |
| 404 | `NOT_FOUND` |
| 409 | `CONFLICT` |
| 503 | `SERVICE_UNAVAILABLE` |

> **Why the catch-all 500 handler exists:** without it, Starlette re-raises and
> the CORS middleware never runs — so the browser reports a *missing
> Access-Control-Allow-Origin header* instead of the 500 that actually happened,
> hiding the real fault. The cause is logged server-side; the client is told only
> that the request failed.

Scanner-originated errors are surfaced with their own codes:
`SCANNER_UNAVAILABLE` (retryable), `SCANNER_FAILED`, `INVALID_SCANNER_RESPONSE`,
`INVALID_ARTIFACT_REFERENCE`, `ARTIFACT_UNAVAILABLE` (retryable),
`INVALID_TARGET`, `TARGET_PREPARATION_FAILED`, `UNSUPPORTED_TARGET_TYPE`.

---

## 15. Frontend — what the interface must present

This section specifies the **interface contract**, not an implementation. It says
what must be on screen and why the platform's own guarantees demand it. Layout,
component decomposition, and visual language are the designer's to decide; the
obligations below are not.

The rule that generates every requirement here:

> **Trinetra's product claim is evidence, not scores.** The engines deliberately
> refuse to produce a number when evidence is missing (P3), and attach provenance
> to every number they do produce (P4). An interface that renders only the
> conclusion throws away the thing that makes this platform defensible. **If the
> backend distinguishes it, the UI must show it.**

---

### 14.1 The four obligations

Every screen inherits these. They are not styling preferences — each one exists
because the backend would otherwise be lying through its own interface.

#### O1 — "No score" must never look like "score of zero"

The engines return `final_score = None` in three distinct situations:
policy short-circuit (already-broken or already-quantum-safe algorithm),
dependency-only finding, and insufficient evidence (`NEEDS_CONTEXT`). A gauge at
zero, an empty progress bar, or a dash all read as *"low risk"* — the opposite of
what two of these three mean.

**Required:** absence of a score is its own visual state, distinct from a low
score, and it carries the reason. `NEEDS_CONTEXT` must name the missing fields
(the backend already returns `missing_fields_json`) and offer the correction path.

#### O2 — Every number displays its provenance

The backend records, per field, whether a value came from `user`,
`scanner_evidence`, `org_preset`, or `unknown`. A user-confirmed migration time
and an organisation default are different epistemic objects and must not render
identically.

**Required:** a visible, consistent provenance treatment attached to each
displayed value — not buried in a tooltip, because a reviewer skimming for
"what do we actually know here?" will not hover over twenty fields.

#### O3 — A projection is never stated as a fact

`projected_break_year = 2036` is *the first year a cited model crosses a stated
scenario*, under assumptions the backend ships alongside it. Rendered as
"Breaks: 2036" it becomes a prediction the project explicitly disclaims
(section 21).

**Required:** wherever a year, an M, or a deadline appears, the scenario name and
the confidence level appear with it, and the underlying assumptions are reachable
without leaving the finding. Low confidence must be legible at a glance — a
crossing in the curve's extrapolated tail is low-confidence *by construction*,
and the interface must not flatter it.

#### O4 — Every finding is one click from its evidence

`location` is stored as `"svc/auth.py, line 20"` precisely because the first
thing anyone does with a finding is go look at it. `raw_cbom` preserves the
untouched scanner output.

**Required:** file and line always visible on a finding; the raw CBOM component
reachable from the detail view; the scanner that produced it named.

---

### 14.2 Required surfaces

Eight surfaces. Each is defined by **what question it answers** and **what it
must contain**. Nothing here prescribes how it looks or how it decomposes.

---

#### S1 — Entry / public

*Answers: what is this, and should I sign in?*

Public, no authenticated data. Must state the problem (harvest-now-decrypt-later,
the 2027–2029 Indian migration window), what Trinetra does in its four stages,
and what makes it different — including, honestly, that comparable tools exist.

**Design note:** this is the only surface where persuasion is the goal. Every
other surface is an instrument, and instruments do not persuade.

---

#### S2 — Authentication

*Answers: who am I?*

Username and password only. Must surface the backend's stable error codes as
distinguishable states — `UNAUTHENTICATED` (wrong credentials) and
`SERVICE_UNAVAILABLE` (Redis down) are different problems with different user
actions, and must not collapse into one generic failure message.

Must also handle the **session-restore window**: on reload the cookie may still
be valid while the CSRF token is gone. A blank screen or a premature bounce to
login during that check is a bug, not a loading state.

---

#### S3 — Portfolio overview

*Answers: how exposed is the organisation, and what do I do first?*

| Must contain | Why |
|---|---|
| Count by priority band (P0 / P1 / P2) | The primary triage axis |
| Count of `NEEDS_CONTEXT` findings | **Load-bearing.** These are not low risk — they are unassessed. Hiding them inside "P2" or omitting them misrepresents coverage |
| Worst offenders, ranked | The actual next action |
| Active scenario and planning horizon | Every number on the page is conditional on these two values |
| Scan history with status | `failed` scans mean the inventory is incomplete |

**The count of unassessed findings is as important as the count of P0s.** A
dashboard that reports "3 critical findings" while silently holding 40
`NEEDS_CONTEXT` items is telling the user they are safer than they are. Coverage
and severity are separate facts and must be presented as such.

---

#### S4 — Scan launch and live progress

*Answers: is it running, and did it work?*

Must let the user choose a target type from the **backend-reported capability
list** (`GET /api/scans/capabilities`) — never a hardcoded list, since a
deployment may not enable all three scanners.

Must render the state machine honestly:

```
queued  →  running  →  completed
                   ↘   failed   (error_code + actionable message)
```

- `failed` must show the backend's message and code. `TARGET_PREPARATION_FAILED`
  (fix your URL) and `SCANNER_UNAVAILABLE` (retry later) call for different user
  actions and must be distinguishable.
- **The WebSocket is best-effort.** `progress.publish` swallows its own failures
  by design, so the UI must not treat a silent socket as a failed scan — it must
  fall back to polling and say it is doing so. A completed scan that looks stuck
  because Redis dropped a message is a false alarm the architecture explicitly
  chose to tolerate; the interface must absorb it.
- Optional scan-wide business context is collected here, and it must be clear
  this becomes the `org_preset` tier for every finding — overridable per artefact,
  not a commitment.

---

#### S5 — Inventory

*Answers: what did we find, and which of it matters?*

The working surface. Must present, per finding: algorithm and key size, asset
type, location, priority band, score **or its absence**, and the scanner that
found it.

**Required behaviours:**

- Filter by priority, asset type, scanner, and **assessment state** — the last
  one so "show me everything that could not be assessed" is one interaction.
- Sort by score with a defined, visible position for unscored findings. Sorting
  them silently to the bottom buries exactly the items needing human input.
- Handle `library` findings as a distinct class. They are dependency evidence,
  never scored, and presenting them alongside scored algorithm findings without
  distinction invites the reader to infer a missing risk verdict.
- Bulk selection only if it maps to a real backend capability. Do not design
  affordances the API cannot honour.

---

#### S6 — Finding detail

*Answers: why does this finding say what it says?*

The most important surface in the product, and the one where the two-track model
either becomes comprehensible or does not. It must present, at minimum:

**Identity** — algorithm, key size, purpose, asset type, location (file + line),
discovering scanner, raw CBOM component reachable.

**Track A, Mosca** — X, Y, Z, each with provenance; Z's basis
(`org_horizon` / `resource_model` / `unavailable`); the inequality's outcome and
the shortfall in years; **the full evidence list behind X**, since multiple
categories may have been considered and the longest governed.

**Track B, resource** — Q as logical qubits *and* logical gates; the attack model
cited; P(t) at the crossing; the projected year; M; the scenario; **the
assumptions block** (error-correction scheme, logical-qubit definition, physical
error rate, caveats); the projection status.

**The combination** — every factor, its points, its ceiling, its basis, its
provenance. Not a total with a breakdown hidden behind a disclosure — the
itemisation *is* the content. A factor contributing zero because no evidence
supported it must be visually distinct from a factor contributing zero because
the evidence showed no risk. Those look identical as numbers and mean opposite
things.

**The recommendation**, when one exists — current versus proposed side by side,
parameter set, hybrid status, cited FIPS sources, and **the unmeasured dimensions
labelled as unmeasured**. There is no composite fit score by design; an interface
that computes one, or implies one through a progress bar or a star rating,
directly contradicts the engine.

**Assessment history** — assessments are append-only so that *"why was this P0
last week?"* is answerable. If the UI shows only the latest, the append-only
table is storage nobody can read.

**Context correction** — the path by which a user promotes a field to the `user`
provenance tier. Must make clear that saving appends a new assessment rather than
editing the old one, and must show the resulting change.

---

#### S7 — Risk configuration

*Answers: what assumptions is every number on every other screen resting on?*

Admin only. Controls the planning horizon, the scenario
(conservative / baseline / aggressive), and the active profile versions.

**This is the platform's most consequential screen and must be treated as such.**
Changing any value re-scores **every artefact in the system** and appends a new
assessment to each. The interface must:

- State that consequence *before* the change, with the affected count.
- Show the capability curve, and show it **scaled by the selected scenario** —
  the scenario scales P(t), never Q, and a curve that does not move when the
  scenario changes teaches the user the wrong model.
- Mark where the curve stops being roadmap-anchored and starts being
  extrapolated. Confidence is derived from this boundary; hiding it hides why a
  verdict is low-confidence.
- Cite the sources behind every active profile, reachable from here.
- Report `artefacts_rescored` after the change — the number is returned precisely
  so the recalculation is visible rather than silent.

---

#### S8 — Export

*Answers: how do I get this out of Trinetra?*

CycloneDX-JSON (machine-readable, the standard deliverable) and PDF (the
human-readable report). Must make the distinction clear, and must reflect that
generation is asynchronous and idempotent.

---

### 14.3 What the interface must never do

Each of these would contradict a guarantee the backend makes. They are failure
conditions, not style opinions.

| Never | Because |
|---|---|
| Render a missing score as zero, a dash, or an empty meter | Conflates "unassessed" with "low risk" — inverts the meaning of two of three null cases |
| Show a value without its provenance | Erases the distinction the backend spent a whole table recording |
| Show a break year without scenario and confidence | Converts a stated projection into an unqualified prediction |
| Compute or imply a composite recommendation confidence | The engine deliberately returns null; a bar or rating manufactures the certainty it refused |
| Average the two tracks, or present them as one meter | They are independent evidence about different questions; the engine adds, never averages |
| Hide the score itemisation behind a disclosure | The breakdown is the product; the total alone is what every other tool already ships |
| Treat the guard as security | Route guards are navigation. The backend authorizes every request; UI state is never the boundary |
| Persist the CSRF token to storage | It is memory-only by design; writing it to `localStorage` reintroduces the attack it prevents |
| Show only the latest assessment | Makes the append-only history unreadable and its central question unanswerable |
| Present `library` findings as if unscored means unassessed | They are dependency evidence and are correctly never scored |
| Treat WebSocket silence as scan failure | Progress is explicitly best-effort; the scan is almost certainly fine |

---

### 14.4 Visual language — principles, not specifications

The design is open. These constraints come from the data, and only these.

**Encode four assessment states, not two.** Priority band, unassessed
(`NEEDS_CONTEXT`), policy-decided (already broken / already safe), and
informational (`library`). A palette built only for P0/P1/P2 will force the other
three into a band where they do not belong.

**Give confidence its own channel, independent of severity.** A high-score
low-confidence finding and a high-score high-confidence finding must be
distinguishable at a glance without reading. If confidence is encoded in the same
channel as severity, one will be read as the other.

**Provenance needs a persistent, quiet treatment.** It appears on nearly every
value, so it must be legible without competing for attention — visible while
scanning, not demanding to be looked at.

**The score breakdown is a first-class object.** Seven factors, each with points,
a ceiling, a basis and a provenance. It must remain readable at that density
without collapsing into a wall of numbers — this is the hardest single design
problem in the product, and it is the one that distinguishes Trinetra from tools
that print a severity label.

**Accessibility is a correctness requirement here.** Priority and confidence must
never be conveyed by colour alone. A user who cannot distinguish red from amber
must still be able to triage, and a finding's state must survive being read
aloud.

**Dark mode is an operational requirement, not a preference.** SOC analysts work
in dark rooms for long shifts. Both themes are primary.

**The interface should feel like an instrument, not a dashboard.** Its job is to
let a careful person check the platform's reasoning. Every element that draws
attention to itself rather than to the evidence is working against the product's
central claim.

---

### 14.5 Technical constraints the design must respect

Not design decisions — facts the interface has to live with.

| Constraint | Consequence for design |
|---|---|
| Session cookie is HttpOnly; CSRF token is memory-only | A reload has a restore window before identity is known. Design that state; do not flash the login screen |
| Every state-changing request needs `X-CSRF-Token` | Mutations can fail with `FORBIDDEN` after a session expires mid-edit. Unsaved context corrections must survive that |
| Errors carry stable codes | Branch on `code`, never on message text. Messages are for humans and will change |
| 4xx must never be retried | The answer will not change; retrying only delays the message the user needs |
| Scanner availability is deployment-dependent | Target types come from the capability endpoint, always |
| Context correction appends an assessment | It is not an edit. The UI must show a new verdict was produced, not that a value was overwritten |
| Settings change re-scores everything | Cached finding data across the whole app is stale afterwards |
| Scans are long-running and idempotent | Re-submission is safe; the interface should say so rather than blocking the user defensively |
| Reports generate asynchronously | Requesting and downloading are separate moments |

---

### 14.6 The test of the design

One question settles most decisions:

> **Could a reviewer who distrusts this verdict use the interface to check it —
> and find either the evidence or an honest statement that it is missing?**

If yes, the design serves the platform. If the interface can only be trusted
rather than checked, it has undone in presentation what the engines were built to
guarantee.

---

## 16. Security architecture

### Trust boundaries

| Boundary | Control |
|---|---|
| Browser → API | Opaque Redis session cookie (HttpOnly, Secure, SameSite=strict), CSRF token, RBAC |
| API → scanners | Bearer token ≥32 chars, SHA-256 constant-time compare, private internal network, ports unpublished |
| Scanner → filesystem | `targetpath.Resolve` rejects traversal outside the input root; inputs mounted read-only |
| Scanner → CBOM | Validated against the frozen schema in **Go and again in Python** |
| Worker → git | `--depth 1`, timeout-bounded, destination inside `scan-workdir` only |
| Secrets | HSM / KMS import is **metadata only** — key material is never read |

### Session design

```
cookie:  trinetra_session = <48 bytes urlsafe random>     HttpOnly Secure SameSite=strict
redis:   trinetra:session:<id> → {user_id, username, role, csrf_token}   TTL 8h
```

The cookie is **opaque**. No authorization data is trusted from it — role comes
from Redis, and then from PostgreSQL:

```python
# The database remains authoritative if an admin changed a user's role after the
# browser signed in; stale Redis session claims cannot retain privileges.
```

A malformed cache record is never treated as an authenticated session — it is
deleted and the request is rejected. A Redis outage returns `503`, never a
silent auth bypass.

### RBAC

| Role | Can |
|---|---|
| **Admin** | everything: settings, user provisioning, scan deletion |
| **Analyst** | create scans, correct artefact context, generate reports |
| **Viewer** | read-only |

Enforced by a `require_roles(*roles)` dependency factory on each route, plus
`require_csrf` on every state-changing route
(`dependencies.py`).

### Bootstrap

Initial users are **never hard-coded**. A deployment supplies
`BOOTSTRAP_ADMIN_USERNAME` / `BOOTSTRAP_ADMIN_PASSWORD` once, then removes the
password from its environment after the first Admin login.

### Container hardening

Every application container runs with:

```yaml
read_only: true                    # immutable root filesystem
tmpfs: [ /tmp:size=…,mode=1777 ]   # the only writable path
cap_drop: [ ALL ]                  # no Linux capabilities
security_opt: [ no-new-privileges:true ]
init: true                         # proper PID 1, no zombie processes
```

### Request hardening

- Scanner HTTP bodies capped at **1 MiB** (`maxRequestBytes`).
- `scan_id` must match a strict UUID v1–v5 regex before any work begins.
- Session IDs longer than 256 chars are rejected without a Redis round-trip.
- Scanner error messages are `SafeError` values — a fixed code and a
  non-leaking message. Internal causes are logged, never returned.
- Job payloads are small, **secret-free**, and idempotent by construction.

### Supply chain

`codeql.yml` (static analysis) and
`dependency-review.yml` (dependency diff
gate) run on every PR.

---

## 17. Deployment & runtime topology

### One command

```bash
docker compose up --build
```

Startup ordering is fully declared, not raced:

```
postgres  (healthcheck: pg_isready)
redis     (healthcheck: redis-cli ping)
   ↓ service_healthy
migrate   (alembic upgrade head, restart: "no")
   ↓ service_completed_successfully
seed-demo-targets  (copies fixtures into scan-workdir, restart: "no")
   ↓
scanner-source · scanner-container · scanner-cloud-hsm
   ↓ service_started
backend  (healthcheck: GET /health)  ·  worker  (healthcheck: celery inspect ping)
   ↓ service_healthy
frontend (nginx, healthcheck: GET /healthz)
```

### Published ports

| Host | Service |
|---|---|
| `5173` | frontend (nginx on 8080 internally) |
| `8000` | backend API |
| `5433` | postgres (5432 internally) |
| `6379` | redis |
| — | **all three scanners: never published** |

### Configuration

All settings come from the environment via Pydantic `BaseSettings`
(`config.py`), read from `.env` at the repo root.

| Variable | Default | Note |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg2://…:5433/trinetra` | |
| `REDIS_URL` | `redis://localhost:6379/0` | |
| `SESSION_COOKIE_SECURE` | `true` | **Local HTTP dev must opt out explicitly** |
| `SESSION_COOKIE_SAMESITE` | `strict` | |
| `SESSION_TTL_SECONDS` | `28800` (8h) | |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:5173,…` | |
| `TRINETRA_SCANNER_TOKEN` | dev placeholder | **≥32 chars enforced at startup** |
| `SOURCE` / `CONTAINER` / `CLOUD_HSM_SCANNER_URL` | internal DNS names | |
| `ARTIFACT_STORE_PATH` / `SCAN_WORKDIR_PATH` | repo-relative | Large blobs stay out of Postgres |
| `SCAN_TIMEOUT_SECONDS` | `600` | |
| `WORKER_MAX_RETRIES` | `3` | |
| `BOOTSTRAP_ADMIN_USERNAME` / `_PASSWORD` | unset | First-run only |

> Raw scan inputs and generated CBOM documents live **outside the database** so
> large blobs never bloat Postgres and re-scans version cleanly.

---

## 18. Failure handling & reliability

### Celery configuration and why

```python
task_acks_late = True              # ack only after success → crash ⇒ redelivery
task_reject_on_worker_lost = True  # a killed worker's job goes back on the queue
worker_prefetch_multiplier = 1     # no hoarding; long scans distribute fairly
visibility_timeout = 2 × scan_timeout   # never redeliver a scan still running
broker_connection_retry_on_startup = True
task_serializer = "json"           # no pickle — no deserialization gadget surface
```

### Retry policy

Only **temporary** failures retry, with exponential backoff capped at 30s:

```python
if exc.retryable and self.request.retries < settings.worker_max_retries:
    raise self.retry(countdown=min(2 ** (retries + 1), 30), ...)
```

`SCANNER_UNAVAILABLE` and `ARTIFACT_UNAVAILABLE` are retryable. `INVALID_TARGET`
is not — retrying a bad path just delays the message the user needs.

### Idempotency at three levels

1. **HTTP** — `Idempotency-Key` header on `POST /api/scans` and report creation,
   backed by a **unique database index** on `(requested_by, idempotency_key)`.
2. **Celery** — `task_id = f"scan-{scan_id}"` deduplicates enqueues.
3. **Execution** — `execute_scan` resumes at ingest if the immutable CBOM already
   exists, and `count_artefacts_for_scan` prevents double-insertion.

### Failure guarantees

| Failure | Result |
|---|---|
| Scanner unreachable | Retried ×3, then `failed` + `SCANNER_UNAVAILABLE` |
| Scanner crash | `failed` with the scanner's safe message |
| Bad git URL | `failed` + `TARGET_PREPARATION_FAILED`, not retried |
| Path traversal attempt | Rejected at `targetpath.Resolve`, before any I/O |
| Worker killed mid-scan | `acks_late` redelivers; execution resumes at ingest |
| Redis down (progress) | Scan **completes normally**; only live progress is lost |
| Redis down (sessions) | `503` — never a silent auth bypass |
| Postgres connection drop | `pool_pre_ping=True` — a scan can idle long enough to matter |
| Unhandled exception | Logged server-side, `500 INTERNAL_ERROR` with CORS headers intact |

---

## 19. What must be tested

Not a file listing — a list of the properties that, if they break, make the
platform dishonest rather than merely broken. These are the tests worth writing
first.

### 19.1 The engines — pure, so exhaustively testable

Because the engines have no I/O, every one of these is a plain function call with
no fixtures.

| Property | The failure it catches |
|---|---|
| Missing evidence yields `None`, never a number | The single most important guarantee in the platform (P3) |
| A factor with no evidence contributes zero **and is labelled** | A silent default masquerading as a measurement |
| No score unless **both** tracks produced a result | Ranking artefacts on non-comparable inputs |
| Policy short-circuits return no score | Implying a measurement of MD5 that was never made |
| Identical inputs → identical outputs | Loss of reproducibility, which breaks re-scoring |
| Confidence is the weaker track, downgraded on missing evidence | Confidence inflation |
| A capability year missing either dimension cannot satisfy Q | Half an answer scoring as an answer |
| A scenario scales P(t) and **never** Q | The attack requirement drifting with roadmap optimism |
| Within the strongest evidence tier, the longest lifetime governs | Health records losing to session tokens |
| An unknown algorithm escalates to manual review | A silent fit score of 100 |
| The worked example in section 10 reproduces exactly | Any regression in the whole combination path |

### 19.2 The contract

| Property | The failure it catches |
|---|---|
| A hand-built finding round-trips to a schema-valid document | Schema drift |
| Identical input produces a **byte-identical** document | Non-determinism, which makes diffs meaningless |
| Canonical → CycloneDX → canonical is the identity | The two vocabulary tables drifting out of inverse |
| A document with zero components ingests as an empty result | Treating a clean repository as an error |
| Non-`cryptographic-asset` components are skipped, not rejected | Brittleness against legitimate CBOMs |
| `library` findings never carry an algorithm | The risk engine inventing an attack model from a package name |

### 19.3 Detection quality

| Property | The failure it catches |
|---|---|
| Negative fixtures produce **zero** findings | The `rsa = "some string"` false positive |
| Key size survives from source line to database column | The message-interpolation constraint silently violated |
| Each supported language has a positive fixture | A language claimed but not covered |
| Golden CBOM diffs are reviewed, not regenerated blindly | A rule change quietly altering unrelated output |
| Taint rules fire only on a genuine source→sink path | PII evidence manufactured from a name coincidence |

### 19.4 Orchestration

| Property | The failure it catches |
|---|---|
| A worker killed mid-scan resumes without duplicating artefacts | Redelivery corruption |
| The same idempotency key never creates a second scan | The unique index not doing its job |
| A scanner error leaves the scan `failed`, never `running` | The hang that has no user-visible end |
| Only retryable errors retry | Wasting three attempts on a malformed URL |
| Redis down during progress still completes the scan | Best-effort progress becoming load-bearing |
| A path outside the input root is rejected before any I/O | Traversal |

### 19.5 Authorization

| Property | The failure it catches |
|---|---|
| Every state-changing endpoint rejects a missing or wrong CSRF token | The gap that makes the session cookie exploitable |
| A role downgraded in the database takes effect on the next request | Stale session claims retaining privileges |
| A malformed session record authenticates nobody | Cache corruption becoming an auth bypass |
| Redis unavailable returns 503, never success | Fail-open |
| Password hashes never appear in any response | The leak that only a test will catch |

### 19.6 Interface obligations

These are the section 15 obligations as assertions. They are worth automating
because they regress invisibly — a UI that starts rendering `None` as `0` still
looks fine.

| Property | The failure it catches |
|---|---|
| A null score renders as its own state, not as zero or blank | O1 — "unassessed" reading as "safe" |
| `NEEDS_CONTEXT` names the missing fields | A dead end instead of an action |
| Displayed values carry provenance | O2 — the distinction the backend recorded, erased |
| A break year never appears without scenario and confidence | O3 — a projection presented as a fact |
| No composite recommendation confidence is displayed | Manufacturing certainty the engine refused |
| Unassessed findings are counted separately from low-risk ones | Coverage misreported as safety |
| A zero-evidence factor is distinguishable from a zero-risk factor | Identical numbers, opposite meanings |
| WebSocket silence does not render as scan failure | A false alarm the architecture chose to tolerate |
| The CSRF token is never written to browser storage | Reintroducing the attack it prevents |

### 19.7 Continuous integration

| Gate | Enforces |
|---|---|
| Lint + format, all languages, failing the build | Reviewable diffs |
| Full engine test suite | Everything in 19.1 |
| Scanner tests including negative fixtures | Everything in 19.3 |
| Type-check and build the frontend | The API contract still matching the client |
| Build every image | A Dockerfile that drifted from its code |
| Validate the compose configuration | A stack that cannot start |
| Dependency and static security review | Supply-chain regressions |

**One integration test earns its cost:** a real scan of a known fixture through
the full stack, asserting the expected number of artefacts at the expected
priorities. It is slow, and it is the only test that proves the pieces actually
connect.

---

## 20. Building and extending

### 20.1 What to build, in order

This spec describes a platform, not a directory layout. Organise the code however
the team prefers; what follows is the **dependency order**, because each step
needs the one before it to be testable.

| Step | Build | Done when |
|---|---|---|
| 1 | The `Finding` shape and the CBOM schema | A hand-written finding round-trips to a schema-valid document |
| 2 | The scanner HTTP boundary (auth, path resolution, artifact write) | A stub scanner returns a valid CBOM over an authenticated call |
| 3 | Ingest + the canonical vocabulary | A CBOM becomes rows; purpose and algorithm normalise correctly |
| 4 | The context chain | Every field resolves with the right provenance tier |
| 5 | The capability profile (offline QDK generation) | Q exists for RSA and ECC, with assumptions attached |
| 6 | Both risk tracks, pure | Given a context, both produce results or an honest `None` |
| 7 | The combination engine | The worked example in section 10 reproduces exactly |
| 8 | Orchestration + queue | A real scan runs end to end and survives a worker kill |
| 9 | The API + RBAC | Every endpoint in section 14, authorized and CSRF-protected |
| 10 | The interface | Every obligation in section 15 satisfied |

**Steps 1–7 have no infrastructure dependencies.** They are pure data and pure
functions, and they can be built and tested before a container exists. Doing them
first is what keeps the engines pure — a risk engine written after the database
tends to grow a database call.

### 20.2 The invariants any structure must preserve

Whatever the layout, these must remain true, because the rest of the spec assumes
them:

| Invariant | Why it matters |
|---|---|
| Engines import nothing that does I/O | Otherwise `rescore_all` stops being reproducible |
| One module owns all database access | Otherwise the audit surface is the whole codebase |
| One module owns the CBOM → row mapping | Otherwise scanners diverge in meaning |
| One place translates CycloneDX ↔ canonical, in both directions | Otherwise the two tables drift and purposes silently corrupt |
| One frontend module knows endpoint shapes | Otherwise the CSRF and credential policy is enforced in N places |
| Profiles are data files, never code | Otherwise "which version produced this verdict?" is unanswerable |

### 20.3 Adding a detection rule

1. Match a **call expression, never a bare identifier**.
2. **Interpolate the captured key size into the message** — Semgrep OSS gives you
   no other channel (section 7).
3. Add a positive fixture in each language the rule claims to support.
4. Add a negative fixture if the token is ambiguous. A rule matching `rsa` will
   flag `rsa = "some string"`, and only a negative fixture catches that.
5. Re-generate the golden CBOM and review the diff. An unexpected change in the
   golden file is the rule misfiring.

### 20.4 Adding a scanner

1. Implement the shared scanner interface — authentication, body limits, ID
   validation and graceful shutdown come with it. Do not re-implement the HTTP
   boundary; a second implementation is a second set of security bugs.
2. Reduce output to `Finding` and let the shared builder produce the document.
   **Never let a scanner write its own CBOM.**
3. Decide its network placement deliberately: internal-only by default, egress
   **only** if it genuinely must reach outside. That decision is the blast radius.
4. Register its URL and target type in configuration and in the orchestrator's
   scanner map.
5. Add it to the capability endpoint, so the interface offers it only where it is
   deployed.

### 20.5 Changing a risk weight or policy

1. Create a **new** profile version. Never edit a published one — assessments cite
   it by version, and editing in place falsifies history.
2. Register the version and any schema validation it needs. A malformed profile
   must fail at load, not at scoring time.
3. Activate it through the settings endpoint, which creates a new immutable
   settings version and re-scores every artefact.
4. Verify the re-score count came back, and spot-check that a known finding
   changed in the direction the new policy implies.

### 20.6 Adding an API endpoint

1. Declare its role requirement and, if it changes state, its CSRF requirement.
   These are not optional decorations.
2. Keep database access inside the repository layer.
3. Return the standard error shape with a **stable code**. The interface branches
   on codes, never on message text.
4. Mirror the type on the client, and add it to the query-key registry so
   invalidation cannot drift.

---

## 21. Design boundaries — what Trinetra will not do

These are **design decisions, not gaps**. Each one is a place where a less
careful tool would produce a confident number and be wrong.

- **Predict when quantum computers will break your crypto.** It reports the first
  year a *cited model* crosses a *stated scenario*, with the assumptions attached.
  2036 under profile 2026.1 baseline is a planning scenario, not a prophecy.

- **Invent a number to fill a gap.** Missing evidence produces `NEEDS_CONTEXT`
  naming exactly what is missing.

- **Infer business context from code.** `RSA.generate(2048)` looks identical in a
  payment gateway and a toy script. `resolve_context` explicitly discards the file
  path before resolving criticality.

- **Judge AES without a key size.** `AES.new(key, MODE_GCM)` does not state 128 or
  256, so the finding reports `NEEDS_CONTEXT` rather than guessing.

- **Claim a library proves an algorithm.** OpenSSL being installed is evidence a
  crypto implementation exists, not that any particular algorithm is used — which
  is why `algorithm` is left empty for `library` artefacts.

- **Publish a single confidence score for a recommendation.** A composite number
  would blur published fact and untested assumption. Unmeasured dimensions are
  labelled, not scored.

- **Score an already-broken or already-safe algorithm.** Policy decides those, and
  returns no score, because scoring them would imply a measurement nobody made.

---

<div align="center">

**Trinetra** — *the third eye: seeing the cryptography no one else can.*

Every finding links to a file and a line. Every score shows its arithmetic.
Every profile cites its sources. Nothing is a mystery figure.

</div>
