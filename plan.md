# TRINETRA — PQC Cryptographic Bill of Materials (CBOM) Analytics Platform
## Full Structured Implementation Plan

> **Note on `full architecher.md`:** that file was empty when this plan was written, so the plan derived its architecture from the problem statement. **It has since been filled in (~97 KB) and is now the authority.** Where the two disagree, the architecture doc wins. Reconciled so far:
> - Package layout is `backend/app/` (not `core/`); the canonical contract lives in `app.schemas`.
> - **Phases 2–5 have been fully re-planned against the architecture doc** (2026-09-17): scanners are three Go services behind one HTTP contract, and the risk engine is two tracks plus a versioned profile system.
> - Binary analysis and live TLS probing moved out of the core path to Phases 11B and 11A, matching §7.4. See the R15 note in §1.
> - **Phases 2–3 re-planned again around PQCA CBOMkit** (Apache 2.0, Linux Foundation): adopt a maintained detection engine rather than writing 43 Semgrep rules and an X.509 extractor. CBOMkit does **no** risk scoring, Mosca or PQC recommendation, so Phases 5–6 — the differentiator — remain entirely ours.
> - **Q values are transcribed from cited papers, not computed** (5.1). The doc's RSA figure (Gidney–Ekerå 2021, 20M qubits) is superseded by Gidney 2025 (<1M); build the first profile from the newer one.
> - **Phase 2 is implemented and measured** (see its section). One plan
>   assumption was wrong and is corrected there: `cbomkit-lib` is a Java library,
>   not a CLI, so detection is built behind a pluggable `Engine` interface with
>   Semgrep working today and CBOMkit activated by configuration.
> - Seven principles (P1–P7) now govern the code; P3 in particular ("missing evidence produces *no number*, never a default") is enforced in the Phase 1 schema.

---

## 1. Problem Statement → Deliverable Mapping

Every clause of the problem statement must be satisfied. This table is the **acceptance contract** — the project is not done until every row is checked.

| # | Requirement clause | Where it is built | Done |
|---|---|---|---|
| R1 | Identify & catalogue **algorithms** | Phase 2 (Semgrep + CBOMkit engines) | [x] **done** |
| R2 | Identify & catalogue **keys** | Phase 3.2c (theia + gitleaks) | [ ] |
| R3 | Identify & catalogue **certificates** | Phase 3.2b (theia X.509) | [ ] |
| R4 | Identify & catalogue **protocols** (TLS/SSH/IPsec) | Phase 2 (declared) + **Phase 11A (observed)** | [~] partial |
| R5 | Identify & catalogue **libraries** (OpenSSL, BouncyCastle…) | Phase 3.3–3.4 (Syft PURLs) — *never with an algorithm* | [ ] |
| R6 | Identify & catalogue **hardware modules** (HSM/TPM/PKCS#11) | Phase 4.2–4.3 | [ ] |
| R7 | Identify & catalogue **cloud services** (KMS/ACM/Key Vault) | Phase 4.4 (metadata only) | [ ] |
| R8 | Coverage of **internal AND external facing** apps/infra | Phases 2–4 (internal) + **11A (external)** | [ ] |
| R9 | **Quantum risk assessment** — systems prone to quantum attack | Phase 5.3 (Track B, resource model) | [ ] |
| R10 | Highlight **risks to sensitive data** (HNDL) | Phase 2.3 (taint rules **done**) + Phase 5.5 | [~] evidence done |
| R11 | **Classify** artefacts by type, lifetime, business criticality | Phase 5.5c + context chain | [ ] |
| R12 | **Mosca's algorithm** (X + Y vs Z) applied & categorized | Phase 5.2 (Track A) | [ ] |
| R13 | **Recommend PQC / hybrid alternatives** by risk, latency, cost | Phase 6 | [ ] |
| R14 | Scan **source code repositories** | Phase 2 | [x] **done** |
| R15 | Scan **binaries** | **Phase 11B** (Ghidra; §7.4 extension, not core) | [ ] |
| R16 | Scan **libraries** | Phase 3.2 | [ ] |
| R17 | Scan **container images** | Phase 3 (cbomkit-theia) | [ ] |
| R18 | Report in **standardised formats** (CycloneDX CBOM 1.6) | Phase 2.0 (contract) + Phase 7 (export) | [ ] |
| R19 | Report shows **versions / modes** (AES-128-CBC, RSA-2048…) | Phase 1.2 schema + Phase 2 detection + Phase 7 export | [~] detection done |
| R20 | **Interactive GUI** to visualise scan, risks, results | Phases 8–10 | [ ] |
| R21 | **Usable GUI** — a non-expert can see everything without training *(quality bar on R20, see §4)* | Phase 8.5 + Phases 9–10 + Phase 10B validation | [ ] |

> **⚠ One unresolved tension between the problem statement and the architecture.**
> R15 ("scan **binaries**") is named explicitly in the deliverable, but
> `full architecher.md` §7.4 places Ghidra last, as an optional coverage
> extension on its own queue. Following the architecture means **binary scanning
> is not in the core build** — which leaves a named deliverable unmet if the
> schedule runs out before Phase 11B.
>
> This plan follows the architecture (it is the authority) but does **not** let
> the requirement disappear: 11B is tracked, and R15 stays unticked until it
> ships. **Decide explicitly whether to pull 11B.1–11B.3 forward into P1**; do not
> let it be settled by the clock.

---

## 2. Build Order — Which Part First, and Why

**Decision: Data Model → Source Scanner → Risk Engine → Recommendations → Reports → GUI.**

### Why not frontend first
A GUI is a *renderer of a data shape*. If the CBOM schema isn't frozen first, every scanner change forces a UI rewrite. Starting at the UI means building screens for data that doesn't exist yet — that produces demo-ware that can't be swapped for real output later.

> **But *design* the UI early — just don't *build* it early.** These are different activities, and conflating them is why so many tools end up either rewritten or ugly.
> - **Wireframes, personas and the §4 UX doctrine: start in week 1**, in parallel with the scanner. Paper needs no backend, costs almost nothing, and a layout mistake caught in a sketch costs minutes instead of days.
> - **React code: after Phase 8**, once the API contract is real.
>
> Designing early also **feeds requirements backwards into the backend**: sketching the Mosca timeline is what reveals that Phase 8.7 must recalculate fast enough for a live slider, and sketching the artefact drawer is what reveals that Phase 2 must capture the surrounding code snippet, not just a line number. Those are cheap requirements to discover on paper and expensive ones to discover after the scanner is written.

### Why not the risk engine first
The risk engine consumes artefacts. With no artefacts it can only be tested against hand-written fixtures, so the hardest and most valuable component gets built against fake input and breaks on contact with real scanner output.

### Why the data model (Phase 1) is genuinely first
Everything — scanner, risk engine, recommender, exporter, API, UI — reads and writes the same `CryptoArtefact` record. Freeze it once and all six workstreams can proceed in parallel afterwards. This single decision is what makes the rest of the project parallelisable.

### Why source scanning (Phase 2) before binary/container (Phase 3)
Source scanning gives the highest value per unit of effort: Semgrep over text, no image pulls, no egress, and it produces the realistic artefact stream Phases 5–7 need for testing. The container scanner needs registry access and disk-heavy fixtures; the cloud/HSM scanner needs credentials and hardware. Both are necessary, neither unblocks everyone else.

The architecture agrees and sharpens it (§7.7): Semgrep is *"the primary evidence stream"*, and the source scanner is the only one of the three that needs **no external route at all** — which is also why it is the safest to build and test first.

### The critical path
Now mirrors the architecture's own build order (§7.7), whose phases 1–4 are
called *"the minimum viable platform"* — a scored, cited,
recommendation-bearing CBOM from source code.

```
Phase 1 (Python contract)  ==  DONE
   |
   +--> 2.0  cbom.schema.json + cbom-go   <-- "nothing works before this"
   |      |
   |      +--> Phase 2  source scanner (Semgrep)
   |      +--> Phase 3  container scanner (Syft)     [parallel]
   |      +--> Phase 4  cloud/HSM scanner            [parallel]
   |               |
   |               v
   |         Phase 2.6  INGEST (Python) --> Phase 5 (two-track risk)
   |                                             |
   |         5.1 Q profiles, generated OFFLINE ->+   (can start in week 1;
   |                                             |    no scanner needed)
   |                                             v
   |                                   Phase 6 (recommend) --> Phase 7 (export)
   |                                                                 |
   +--> Phase 8 (API) ---------> Phase 9/10 (GUI) --> Phase 10B (UX gate)
                                      ^
   9.0 wireframes + §4 UX doctrine ---+   (start EARLY, paper needs no backend)

   Phase 11A (live TLS) · 11B (binaries, CVE, NER)  <-- coverage, not core
```

**Two things can start immediately and in parallel with everything else**, because
neither needs a working scanner: the **offline Q profile generation** (5.1) and
the **UI wireframes** (9.0).

### Vertical-slice rule
**From Phase 2 onward, every phase ends with one working end-to-end path.** After Phase 2 the CLI must scan a real repo and print artefacts. After Phase 5 it must print risk verdicts. After Phase 7 it must emit a valid CycloneDX file. Never end a phase with code that only passes its own unit tests.

### Guard against the classic failure
The likely failure mode here is **shipping a scanner with a pretty dashboard but no defensible risk methodology** — because R9–R13 (the intellectual core, and where the problem statement spends most of its words) are invisible in a screenshot while the UI isn't. Phases 5 and 6 are therefore **not compressible**. If time runs short, cut scanner breadth (drop cloud connectors, drop Rust/Go parsers) — never cut Mosca or the recommendation rationale.

---

## 3. Technology Choices

*Superseded by `full architecher.md` §4 and §7, which this table now mirrors.*

| Layer | Choice | Reason |
|---|---|---|
| **Scanners** | **Go 1.26**, services sharing `cbom-go` | Different blast radii: the container scanner needs egress, the source scanner needs none. Separating them means a compromised image pull cannot reach your source tree |
| **Source detection** | **PQCA `cbomkit-lib`** (Apache 2.0, Linux Foundation) | Maintained engine that already resolves key size, mode and padding for Java/Python/Go. Replaces writing 43 Semgrep rules |
| Gap coverage | **Semgrep OSS**, narrow pack | Only for JS/TS and C/C++, which CBOMkit does not cover — *or* declare them out of scope and say so in coverage stats |
| PII→crypto taint | **Semgrep OSS**, taint mode | Nobody supplies this; it is what gives Mosca's X its scanner-evidence tier |
| **Deployment artefacts** | **PQCA `cbomkit-theia`** (Apache 2.0, Go CLI) | Container images + dirs, X.509, keys (via gitleaks), TLS config. Replaces writing a Syft adapter and an X.509 extractor |
| Dependency inventory | **Syft** | Enumerates PURLs so dependency crypto can be scanned and cached offline |
| Q estimation | **Transcribed from cited papers** (Gidney 2025, Roetteler 2017) | ~20 rows with DOIs. More auditable than a computed number, and needs no quantum toolchain at all |
| PQC parameters | **liboqs** | Authoritative FIPS 203/204/205 sizes — and *only* sizes, never a fit score |
| Backend API | **Python 3.12 + FastAPI, SQLAlchemy 2, Pydantic v2** | Ingest, engines, RBAC, orchestration |
| Job queue | **Celery 5 on Redis** | Redis also carries sessions and progress pub/sub |
| Database | **PostgreSQL 16** + JSONB | Relational, with a JSONB pocket for the verbatim CBOM component |
| Frontend | **React 19, TypeScript, Vite, Tailwind, Radix, TanStack Query** | Types generated from OpenAPI |
| Charts / graph | **Recharts** · **Cytoscape.js** | Mosca timeline, risk heatmap, dependency graph |
| Std format | **CycloneDX 1.6 CBOM** | The OWASP standard for cryptographic assets |
| Packaging | **Docker Compose**, three networks | `scanner-internal` is `internal: true` — no external route at all (P7) |

> **Licence discipline is a procurement requirement, not a preference** (§7.2):
> permissive licences for anything linked or redistributed, and every tool must
> run fully offline. Anything needing a cloud account, a login or a vendor
> callback is disqualified from the core path regardless of quality.

### Upstream dependency register
Adopting a tool is not the same as being absolved of it. §7.1: *"every upstream
tool is a source of evidence, never a source of verdicts."*

| Tool | Licence | Offline? | What Trinetra takes | What it deliberately ignores |
|---|---|---|---|---|
| `cbomkit-lib` | Apache 2.0 | Yes (vendor the jar) | Crypto call sites with key size, mode, padding | **Its compliance verdicts** — Trinetra scores, CBOMkit does not |
| `cbomkit-theia` | Apache 2.0 | Yes (vendor the binary) | Certificates, keys, TLS config in images | Any judgement about severity |
| Semgrep OSS | LGPL-2.1 (subprocess) | Yes | Taint paths PII→crypto; gap-language hits | Its severity ratings |
| Syft | Apache 2.0 | Yes | Package inventory and PURLs | Its CycloneDX output; vulnerability claims |
| liboqs | MIT | Yes | FIPS 203/204/205 parameter sizes | Any fit or suitability score |
| Gidney 2025 / Roetteler 2017 | Papers (cited) | n/a | Q values with assumptions | — |

**Three obligations that come with adopting rather than building:**
1. **Measure their accuracy yourself** (2.1a, 2.7e). Adopting a tool does not transfer responsibility for its false positives to its authors.
2. **Pin and vendor every version.** An air-gapped defence deployment cannot pull from Maven or a registry at scan time (P7).
3. **Record name, version and licence in `metadata.tools`.** *A CBOM that cannot say which version of which tool produced it is not an audit artefact.*

---

## 4. UX Doctrine — How the GUI Stays Easy to Use

> The deliverable asks for an *interactive GUI platform to visualise the scan, risks and results*. The hard part is not drawing charts — it is that this tool shows **intrinsically difficult material** (cryptographic artefacts, a quantum threat model, a timeline inequality) to people who are often **not cryptographers**: a CISO, a compliance officer, an application owner. If they open a screen and cannot tell what it means or what to do, the platform has failed regardless of how good the risk engine is.
>
> These rules are binding on Phases 9 and 10. Every UI checkbox must satisfy them; Phase 10B verifies it with real people.

### 4.1 The three users, and what each must see in 10 seconds

The UI is not one audience. Design each screen for a named reader, and label which one it serves.

| Persona | Opens the tool to answer | Must reach it in | Primary screens |
|---|---|---|---|
| **Executive / CISO** — not technical | "How exposed are we, and what will it cost?" | 1 screen, 0 clicks | Dashboard, Mosca timeline, executive report |
| **Security analyst** — the daily driver | "Which findings are real, and which do I fix first?" | ≤ 3 clicks to evidence | CBOM Explorer, HNDL view, risk register |
| **Developer / app owner** — arrives from a ticket | "What is wrong in *my* code and what do I change it to?" | deep-link straight to the artefact | Artefact drawer, recommendation workspace |

- [ ] **4.1a** Every screen names its primary persona in the design spec
- [ ] **4.1b** A persona switcher (or role-based default landing page) so each user starts where they belong

### 4.2 Progressive disclosure — the anti-overwhelm rule

A CBOM can hold 100,000 artefacts. Showing all of it at once is the single biggest usability risk in this product.

- [ ] **4.2a** **Three-layer depth on every view: summary → list → detail.** Never open on the deepest layer
- [ ] **4.2b** Dashboard shows **at most 5 headline numbers**. Everything else is one click down
- [ ] **4.2c** Advanced controls (risk weights, rule toggles, raw JSON) live behind "Advanced" — visible, not absent
- [ ] **4.2d** Tables open with a **sensible default column set**, not every field; the rest is opt-in
- [ ] **4.2e** Default sort is **always by risk, descending** — the most important row is the first row, everywhere, with no user action

### 4.3 Plain language — no unexplained jargon

The domain vocabulary (Mosca, HNDL, CRQC, ML-KEM, Grover, Shor) is unavoidable, but it must never appear cold.

- [ ] **4.3a** **Every acronym has an inline `ⓘ` tooltip on first appearance on each screen** — "CRQC: a cryptographically relevant quantum computer, i.e. one powerful enough to break RSA"
- [ ] **4.3b** Each finding carries a **one-sentence plain-English summary** above the technical detail: *"This login service uses RSA-2048 key exchange. A future quantum computer could decrypt traffic recorded today."*
- [ ] **4.3c** A built-in **glossary page**, linked from every tooltip
- [ ] **4.3d** Risk bands use **words plus colour plus icon** (`CRITICAL 🔴`), never colour alone
- [ ] **4.3e** No raw enum values or snake_case ever reach the screen (`HARDWARE_MODULE` → "Hardware module")

### 4.4 Every screen answers "so what do I do now?"

An inventory that does not lead to an action is a spreadsheet.

- [ ] **4.4a** Every finding view has a **primary action button** (View evidence / See recommendation / Assign owner / Accept risk)
- [ ] **4.4b** Risk numbers are **never bare** — always paired with the reason and the suggested next step
- [ ] **4.4c** The dashboard carries a **"Top 5 things to fix this quarter"** panel — the single most useful element for a non-expert
- [ ] **4.4d** Empty states teach rather than apologise: no scans yet → a "Run your first scan" call to action, not a blank page

### 4.5 Never leave the user staring at nothing

Scans run for minutes. Silence reads as a broken product.

- [ ] **4.5a** **Live progress with a real percentage and the current stage** ("Scanning Java sources… 1,204 / 5,880 files"), streamed over WebSocket
- [ ] **4.5b** **Partial results render as they arrive** — the artefact table fills during the scan rather than after it
- [ ] **4.5c** Skeleton loaders, never spinners on blank pages
- [ ] **4.5d** Every async action gives immediate feedback (toast / inline state) within 100 ms
- [ ] **4.5e** Errors state the cause *and* the fix ("Could not clone repo: authentication failed. Add a deploy token in Settings → Credentials"), never a stack trace or an error code alone

### 4.6 Trust: show the evidence, admit the gaps

Security users reject tools they cannot verify. Transparency *is* a usability feature here.

- [ ] **4.6a** Every artefact is **one click from its source evidence** — syntax-highlighted code at file:line, certificate fields, binary symbol
- [ ] **4.6b** Confidence is **shown, not hidden** (High / Medium / Low), with the detection method named
- [ ] **4.6c** Mosca verdicts display **their inputs (X, Y, Z) and the arithmetic** — never a bare score
- [ ] **4.6d** **Coverage gaps appear in the UI**, not just the report: "3 binaries were stripped and could not be fully analysed"
- [ ] **4.6e** One-click "mark as false positive" with a reason — and it must visibly stick on rescan

### 4.7 Navigation and orientation

- [ ] **4.7a** Persistent left nav; the current location is always obvious
- [ ] **4.7b** Breadcrumbs on every drill-down (Org → Application → Component → Artefact)
- [ ] **4.7c** **Every view is URL-addressable and shareable** — filters, tabs and selected artefact live in the URL, so an analyst can paste a link to a finding into a ticket
- [ ] **4.7d** Browser back always does the expected thing; drawers and modals do not trap the user
- [ ] **4.7e** Global search (`/` or `Ctrl-K`) reaches any application, algorithm or artefact from anywhere
- [ ] **4.7f** No screen is more than **3 clicks from the dashboard**

### 4.8 Consistency and visual language

- [ ] **4.8a** **One risk colour scale used identically everywhere** — the same red means the same severity on every chart, badge and table row
- [ ] **4.8b** A shared component library; a table, a badge and a chart behave the same on every page
- [ ] **4.8c** Consistent iconography per asset type (key, certificate, algorithm, library, HSM, cloud)
- [ ] **4.8d** Dates always absolute and unambiguous (`2026-03-14`), with relative time as a secondary hint
- [ ] **4.8e** Numbers are formatted and humanised (`12,480`, `2.3 GB`), never raw

### 4.9 Accessibility — non-negotiable, not a polish item

- [ ] **4.9a** **WCAG 2.1 AA** contrast across light and dark themes
- [ ] **4.9b** **Colour is never the only carrier of meaning** — critical for a risk tool, and for the ~8% of male users with colour-vision deficiency. Always colour + text label + shape/icon
- [ ] **4.9c** Full keyboard operability: tab order, focus rings, `Esc` closes overlays, arrow keys in tables
- [ ] **4.9d** ARIA labels and live regions for scan progress; screen-reader pass on the core flows
- [ ] **4.9e** Charts have accessible text alternatives and an underlying data table
- [ ] **4.9f** Respects `prefers-reduced-motion`

### 4.10 Performance as a usability property

- [ ] **4.10a** Artefact table stays smooth at **100k rows** (virtualised rendering)
- [ ] **4.10b** Filter and search feel instant (< 200 ms perceived; debounced server queries)
- [ ] **4.10c** The Mosca `Z` slider recalculates **live** — this interactivity is what makes the concept click
- [ ] **4.10d** Charts degrade gracefully at high cardinality (top-N + "other", not 4,000 illegible slices)

### 4.11 Onboarding — usable on first open, without a manual

- [ ] **4.11a** First-run guided tour of the four core screens (skippable, re-runnable)
- [ ] **4.11b** **Demo dataset loadable in one click** so a new user sees a populated product immediately, not an empty shell
- [ ] **4.11c** Contextual help (`?`) on every complex visualisation, explaining how to read it
- [ ] **4.11d** The scan wizard has sane defaults — a valid scan should be launchable by filling **one field**

---

# PHASE 0 — Foundation & Scaffolding
*Goal: a repo anyone can clone and run in one command. No product logic yet.*

- [ ] **0.1** Read / reconcile `full architecher.md`; if still empty, record this plan as the source of truth
- [ ] **0.2** Monorepo layout:
  ```
  trinetra/
    core/           # shared schema, risk, recommend (imported by everything)
    scanner/        # detection engines
    api/            # FastAPI service
    web/            # React GUI
    cli/            # trinetra CLI entrypoint
    rules/          # YAML rule packs (algorithms, libraries, mappings)
    tests/
      fixtures/     # deliberately vulnerable sample repos/binaries/images
    docs/
    docker/
  ```
- [ ] **0.3** Python tooling: `pyproject.toml`, `uv`/`poetry`, `ruff`, `mypy`, `pytest`
- [ ] **0.4** Node tooling: Vite, TypeScript strict, ESLint, Prettier
- [ ] **0.5** `docker-compose.yml`: api + worker + postgres + redis + web
- [ ] **0.6** CI (GitHub Actions): lint, typecheck, test on every push
- [ ] **0.7** `.env.example` + config loader (pydantic-settings)
- [ ] **0.8** Structured logging (`structlog`) + error-handling conventions
- [ ] **0.9** **Build the fixture corpus**: a Java/Spring app, a Python app, a Node app, a Go binary, a Dockerfile — each containing known-bad crypto (MD5, DES, RSA-1024, ECB mode, hardcoded key, self-signed cert) and known-good (AES-256-GCM, SHA-384). **This is the ground truth every later phase is measured against.**
- [ ] **0.10** `README.md` with quickstart
- [ ] **0.11** **Start the UX track now, in parallel** *(§4, and it runs alongside Phases 1–7 rather than waiting for them)*
  - [ ] Write down the three personas and the question each must answer *(§4.1)*
  - [ ] Paper-sketch the four core screens — no tooling required
  - [ ] Note any backend requirement the sketches reveal, and fold it into the relevant phase **before that phase is built**

**Exit criteria:** `docker compose up` works; `pytest` is green; the fixture corpus is committed and labelled; personas and first sketches exist.

---

# PHASE 1 — Canonical Data Model *(THE KEYSTONE — before anything else)*
*Goal: freeze the schema every other component depends on.*

- [x] **1.1** `AssetType` enum: `ALGORITHM | KEY | CERTIFICATE | PROTOCOL | LIBRARY | HARDWARE_MODULE | CLOUD_SERVICE | RELATED_MATERIAL` → **covers R1–R7**
- [x] **1.2** `CryptoArtefact` core record:
  - `id` (deterministic hash — the same artefact keeps its identity across rescans)
  - `asset_type`, `name`, `oid`
  - `primitive` (block-cipher / hash / signature / KEM / KDF / MAC / AEAD / DRBG)
  - **`version`, `mode` (CBC/GCM/ECB/CTR), `padding`, `key_size`, `curve`** → **satisfies R19**
  - `nist_quantum_security_level` (1–5, or 0 = broken by Shor)
  - `evidence`: file path, line number, code snippet, detection method, confidence
  - `source` (which scanner produced it), `first_seen`, `last_seen`
- [x] **1.3** `KeyArtefact`: type, size, creation date, expiry, rotation period, storage location (file / env var / KMS / HSM), exposure flag
- [x] **1.4** `CertificateArtefact`: subject, issuer, serial, `not_before`/`not_after`, signature algorithm, public-key algorithm + size, SAN, chain depth, self-signed flag
- [x] **1.5** `ProtocolArtefact`: protocol, version (TLS 1.0–1.3, SSHv2), cipher suites, KEX groups, negotiated parameters
- [x] **1.6** `LibraryArtefact`: name, version, purl, FIPS status, PQC-support flag
- [x] **1.7** `HardwareModuleArtefact`: vendor, model, PKCS#11 slot, firmware, FIPS 140-2/3 certificate number
- [x] **1.8** `CloudServiceArtefact`: provider, service (KMS/ACM/KeyVault/CloudHSM), region, key spec, managed vs customer-managed key
- [x] **1.9** `Application` / `System` record: owner, business criticality (1–5), data classification, internal-vs-external exposure, data retention years → **feeds R11 and R12**
- [x] **1.10** `Dependency` edges (app → library → algorithm) for the graph view
- [x] **1.11** `ScanResult` envelope: scan id, target, timestamp, scanner versions, artefact list, coverage statistics
- [x] **1.12** Pydantic models + JSON Schema export + SQLAlchemy tables + Alembic migration
- [x] **1.13** Round-trip tests: object → JSON → DB → JSON → object

**Exit criteria:** the schema is versioned and frozen; every later phase imports from `app.schemas` only. **Met** — 132 tests passing, lint clean, migration verified against the models at column level. Note: the package lives at `backend/app/` (not `core/`) to match `full architecher.md`, which was filled in after this plan was written.

---

# PHASE 2 — Source Discovery ✅ *(R14, R1, R4 · pluggable engines)*

> **Status: complete.** 94 Go tests · 161 Python tests · 29 rules linted ·
> precision 100%, recall 100% on the labelled corpus (24/24 sites, 0 false
> positives). Verify with `python scripts/benchmark_accuracy.py`.

> **Re-planned twice, then adjusted once during implementation.**
> The plan assumed `cbomkit-lib` could be shelled out to like a CLI. **It cannot:
> it is a Java library, and CBOMkit's other half is a full-stack server
> (Postgres + Quarkus + Vue), not a scanner binary.** Rather than pretend
> otherwise, the scanner was built around a **pluggable `Engine` interface**:
>
> - **`SemgrepEngine` — working today.** Covers all five claimed languages, and
>   supplies the PII→crypto taint analysis no upstream tool provides.
> - **`CBOMkitEngine` — wired and tested against recorded output**, activated by
>   `TRINETRA_CBOMKIT_BINARY` when a JRE and a CLI entry point exist.
>
> This keeps the adoption decision intact (CBOMkit drops in with no rewrite)
> while Phase 2 is genuinely runnable and measurable now. §7.1 is unchanged:
> every engine is *evidence, never a verdict*, and both adapters discard their
> tool's severity and compliance opinions.

### 2.0 The contract ✅
- [x] **2.0a** `cbom-go/cbom` — CycloneDX 1.6 builder, the frozen Go↔Python contract
- [x] **2.0b** Validation is a profile over the format, not a new format
- [x] **2.0c** Namespaced extensions only: `trinetra:key-size-bits`, `trinetra:data-category`, `trinetra:asset-type`, plus detection-method / confidence / rule-id
- [x] **2.0d** **Byte-identical output for identical input** — content-derived `bom-ref`, caller-supplied timestamp, stable sort. Reversed input yields the same document
- [x] **2.0e** Zero components is a **valid result**

### 2.1 Engine abstraction + CBOMkit adapter ✅
- [x] **2.1a** Accuracy measured on our own corpus, not claimed from upstream (`scripts/benchmark_accuracy.py`)
- [x] **2.1b** Key size, mode and padding survive into `cryptoProperties` — asserted on real scanner output
- [x] **2.1c** Tool name, version **and licence** recorded in `metadata.tools`; validation rejects a document without them
- [x] **2.1d** `TRINETRA_CBOMKIT_BINARY` keeps the artefact vendorable; an unavailable engine degrades to a coverage gap
- [x] **2.1e** **Language gap recorded honestly**: `CBOMkitEngine.Languages()` returns java/python/go only, and a test fails if it ever claims more

### 2.2 The adapter — the trust boundary ✅
- [x] **2.2a** Subprocess behind an adapter; CBOMkit invoked only when configured
- [x] **2.2b** Output parsed and **validated**, never trusted — malformed output is a scanner error, not a crash
- [x] **2.2c** Every result reduced to one `cbom.Finding` in canonical snake_case (P6)
- [x] **2.2d** **Their verdicts discarded** — Semgrep's `severity` and CBOMkit's compliance policy are both unmapped
- [x] **2.2e** Original component preserved verbatim in `raw_cbom`
- [x] **2.2f** An absent key size stays absent, so the finding degrades to `NEEDS_CONTEXT`

### 2.3 Data-classification taint rules ✅ *(ours — nobody supplies this)*
- [x] **2.3a** `rules/taint/data-classification-rules.yml`, Semgrep taint mode
- [x] **2.3b** Sources: `aadhaar_number`, `card_number`, `medical_record_id`, credential material
- [x] **2.3c** Sinks: `.encrypt()`, `.update()`, `.doFinal()`, `.Seal()`, `.sign()`
- [x] **2.3d** A reaching path attaches `trinetra:data-category` to the artefacts in that file
- [x] **2.3e** Evidence of what the code protects; the Phase 1 schema still forbids a scanner supplying anything but `data_category`
- [x] **2.3f** Fires only on a genuine source→sink path — zero hits on the negative corpus

> **Implementation note.** A taint result names no algorithm, so it is *evidence
> about a location*, not an artefact. `applyDataCategories` folds it onto the
> crypto findings in the same file. Matching is **per file, not per line**: a
> source→sink path and the cipher construction it flows into are routinely a few
> lines apart, and exact-line matching discarded most real evidence. Where a file
> yields several categories the artefact takes all of them, and Track A's own
> precedence rule decides which governs — that judgement belongs to the risk
> engine, not to a scanner adapter.

### 2.4 Coverage gap: JS/TS and C/C++ ✅
- [x] **2.4a** Narrow packs for `node:crypto` and the OpenSSL C API — the languages CBOMkit does not cover
- [x] **2.4b** Both load-bearing rules hold across all 29 rules
- [x] **2.4c** **`scripts/lint_rules.py` enforces them mechanically** and already caught two real rule bugs
- [x] **2.4d** Not needed — the gap is filled rather than declared out of scope

### 2.5 The service ✅
- [x] **2.5a** `POST /internal/v1/scan` via shared `scannerapi`
- [x] **2.5b** Bearer auth ≥32 chars, **SHA-256 constant-time compare**, 1 MiB cap, UUID validation, unknown fields rejected
- [x] **2.5c** `targetpath.Resolve` rejects traversal — tested against `../`, absolute POSIX, drive-letter and UNC forms
- [x] **2.5d** `scan-workdir` read-only in the compose topology
- [x] **2.5e** **Safe error messages** — a test asserts the response never echoes a host path or the rejected target
- [x] **2.5f** Never published to the host; graceful shutdown so an in-flight scan is not cut off mid-write

### 2.6 Python-side ingest ✅
- [x] **2.6a** `app/services/cbom_ingest.py` validates **again** in Python (defence in depth)
- [x] **2.6b** Component → artefact per the §9 mapping
- [x] **2.6c** Purpose, primitive, mode and padding normalised through `vocab.py`
- [x] **2.6d** `trinetra:data-category` lifted out as scanner evidence
- [x] **2.6e** Whole component preserved in `raw_cbom`
- [x] **2.6f** Non-`cryptographic-asset` components **skipped, not rejected**
- [x] **2.6g** `library` findings never carry an algorithm — now enforced **four** times: Go `Normalise()`, Go validator, Pydantic, DB CHECK
- [x] **2.6h** One malformed component becomes a visible gap instead of discarding the inventory

### 2.7 Fixtures and accuracy ✅
- [x] **2.7a** Positive fixtures for all five claimed languages
- [x] **2.7b** **Negative fixtures produce zero findings** — bare identifiers, crypto in comments, crypto in docstrings, classes named after algorithms
- [x] **2.7c** Key size survives source → message → CBOM → artefact field, asserted end to end
- [x] **2.7d** Golden CBOM at `tests/golden/positive-fixtures.cbom.json`, regenerated by `go run ./source/cmd/gencbom` and **reviewed on change, never regenerated blindly**
- [x] **2.7e** **Published precision/recall for the pipeline as integrated** — 100%/100%, key-size resolution 5/5, mode resolution 6/6

**Exit criteria — met.** A fixture repo produces a schema-valid CBOM; ingest populates artefacts with key sizes and modes intact; the same input twice is byte-identical.

### Bugs this phase's own tests caught
Worth recording, because each was silent and each would have shipped:

| Bug | Why it mattered |
|---|---|
| **Semgrep skips `tests/` by default** | A fixture corpus yielded **zero findings**. That default is right for a linter and wrong for an inventory — a hardcoded key under `tests/` is still a key. Fixed with `--x-ignore-semgrepignore-files` |
| Dedup key included key size | The same finding with and without a size never merged, defeating the merge that exists to combine engines |
| POSIX absolute paths accepted on Windows | `filepath.IsAbs` is platform-specific, so a traversal blocked in the Linux container passed on a dev machine |
| Node `aes-256-cbc` lost its mode | Parsed as slash-separated, so `createCipheriv` was recorded as plain AES |
| Two rules interpolated uncaptured metavariables | Would have emitted the literal string `$ALGO` as an algorithm name |
| Taint findings dropped entirely | No algorithm → no name → discarded, losing Mosca's X evidence |

---

# PHASE 3 — Deployment Artefact Discovery *(R16, R17, R5, R3, R2 · adopt cbomkit-theia)*

> **`cbomkit-theia` is a near drop-in for this entire phase.** Go CLI, Apache
> 2.0, scans container images *and* directories, emits CycloneDX 1.6, and already
> detects X.509 certificates, public/private/secret keys, TLS cipher suites from
> OpenSSL config, and Java security configuration — using **gitleaks** for secret
> detection.
>
> Writing a Syft adapter and an X.509 extractor is deleted from the plan.

### 3.1 The service
- [ ] **3.1a** Wrap `cbomkit-theia` behind the shared `scannerapi` contract
- [ ] **3.1b** **On `scanner-egress`** — the one service allowed to pull images
- [ ] **3.1c** Pin the version; record it in `metadata.tools`; vendor the binary for air-gapped installs
- [ ] **3.1d** Registry auth; credentials never logged, never written to the artifact store

### 3.2 The adapter
- [ ] **3.2a** Parse and validate theia's CycloneDX; reduce to `cbom.Finding`
- [ ] **3.2b** Map their certificate output to `CertificateDetail`, keeping **signature algorithm and public-key algorithm separate** (authenticity vs confidentiality risk differ)
- [ ] **3.2c** Map detected keys to `KeyDetail` — **fingerprint only, never key material.** Gitleaks finds real secrets; Trinetra must store none of them, and the Phase 1 `Evidence.redacted` flag exists for this
- [ ] **3.2d** Map TLS/cipher-suite config to `ProtocolDetail` with **`is_observed=false`** — this is *declared* crypto; only Phase 11A observes
- [ ] **3.2e** `library` findings carry **no algorithm** (enforced in schema and as a DB CHECK)

### 3.3 Dependency crypto *(the gap theia does not close)*
CBOMkit's own blog notes the plugin "detects only cryptographic assets invoked
directly from the source code." Their Pipeline solves this — **but it runs in
Azure, which fails P7.** Adopt the *pattern*, not the implementation.

- [ ] **3.3a** Generate an SBOM locally (Syft) to enumerate dependencies and their PURLs
- [ ] **3.3b** Cache a CBOM per PURL, so a dependency scanned once is never rescanned
- [ ] **3.3c** Scan uncached dependencies with the Phase 2 engine
- [ ] **3.3d** Entirely offline — no Azure, no external service (P7)
- [ ] **3.3e** *Optional for v1.* It multiplies scan time; a direct-dependency inventory is a defensible first release

### 3.4 Manifests and SBOM ingest
- [ ] **3.4a** `pom.xml`, `requirements.txt`, `package-lock.json`, `go.mod`, `Cargo.toml`, `*.csproj`
- [ ] **3.4b** Ingest existing CycloneDX / SPDX SBOMs as an input source
- [ ] **3.4c** Crypto-library knowledge base with **per-version PQC support** (e.g. OpenSSL 3.5 ships ML-KEM)

**Exit criteria:** scanning `openssl:1.1.1` yields library, certificate and key artefacts, all with empty `algorithm`, and no secret material anywhere in the output.

---

# PHASE 4 — Cloud/HSM Scanner Service *(R6, R7)*

*Goal: the third scanner — key-object metadata from PKCS#11 and cloud KMS.*

> **Reduced from the original plan.** Live TLS probing (testssl.sh) is a §7.4
> extension needing outbound network access — **a fourth scanner service** on
> `scanner-egress`, planned separately as Phase 11A. It is the highest-value
> extension, but it is not core.

- [ ] **4.1** Third Go binary, same contract, same shared module
- [ ] **4.2** PKCS#11 metadata parser: token enumeration, key objects, their type and capabilities
- [ ] **4.3** Emit `hardware_module` artefacts: vendor, model, firmware, FIPS certificate number, **PQC-capable firmware flag** (an HSM that cannot be upgraded is a hardware purchase, not a code change)
- [ ] **4.4** AWS KMS key metadata → `cloud_service` artefacts with key spec and `customer_managed` vs `provider_managed`
- [ ] **4.5** **Metadata only — never key material.** Read-only credentials, documented least-privilege policy, nothing persisted
- [ ] **4.6** Azure Key Vault and GCP KMS *(optional; AWS first)*
- [ ] **4.7** Asset-inventory import (CSV/CMDB) attaching business criticality and data classification to systems

**Exit criteria:** an HSM fixture and a KMS account yield `hardware_module` and `cloud_service` artefacts with no secret material anywhere in the output.

---

# PHASE 5 — The Two-Track Risk Engine *(R9, R10, R11, R12 — THE CORE)*

> **Substantially widened.** The original plan had Mosca alone. The architecture
> specifies **two independent tracks combined additively**, plus the profile
> system that makes every verdict traceable. This is the intellectual core of the
> product and the part a screenshot cannot show.

*Goal: pure functions of `(context, profile)` that produce auditable verdicts.*

### 5.0 The profile system *(build first — every engine reads a profile)*
- [ ] **5.0a** `backend/app/engines/profiles/` with a `@cache`d **validating** loader — a malformed profile fails **at load, not at scoring time**
- [ ] **5.0b** `retention-policy-2026.1.json` — 10 categories, each declaring basis (`legal` / `regulatory_minimum` / `assumption`) and citing a source. Validation requires categories + sources
- [ ] **5.0c** The profile carries its own printed warning: **"Indian statutes mandate retention *minimums*, not confidentiality lifetimes."** `biometric` (30y) and `credential_secret` (5y) are explicitly labelled Trinetra planning assumptions with no statute behind them
- [ ] **5.0d** `quantum-capability-2026.2.json` — P(t) curve, attack models, scenarios. Validation requires curve + scenarios
- [ ] **5.0e** `risk-weights-2026.1.json` — **weights must total the band max** (validated, not assumed)
- [ ] **5.0f** `current-security-2026.1.json` — already-broken algorithms per NIST SP 800-131A
- [ ] **5.0g** Read compatibility for older version strings (`builtin-0.1.0`, `quantum-capability-2026.1`, `nist-pqc-fit-2026.1`) so settings rows written before the newer profiles still load

### 5.1 Q generation — transcribe published estimates, do not compute them
> **Cost decision.** The architecture says run Microsoft QDK offline. That is
> correct but heavier than needed: the deliverable is *a table of ~20 rows with
> citations*, and **the papers already contain those rows.** Transcribing cited
> figures is ~2 days; building an estimator pipeline is ~2 weeks — and the
> transcription is **more** auditable, because a reviewer can check your JSON
> against the paper, which they cannot do with a number your code computed.

- [ ] **5.1a** **No quantum toolchain in the scan path, and none in the build either.** Hand-build `quantum-capability-2026.2.json` from cited literature
- [ ] **5.1b** Per algorithm + key size: logical qubit count, logical gate count (Toffoli or T), **the construction cited by name and DOI**
- [ ] **5.1c** Sources:
  - **RSA** — Gidney 2025, *"How to factor 2048-bit RSA integers with less than a million noisy qubits"* ([arXiv:2505.15917](https://arxiv.org/abs/2505.15917)); code and data on Zenodo, DOI `10.5281/zenodo.15347487`
  - **RSA (historical)** — Gidney–Ekerå 2019/2021 (20M qubits, 8 hours), kept as a second scenario so the **change between them is visible**
  - **ECC** — Roetteler 2017 closed-form formulas; a few lines of Python, no quantum library
- [ ] **5.1d** **Every entry carries an assumptions block** — error-correction scheme, logical-qubit definition, physical error rate, caveats. *A profile entry without an assumptions block fails validation on load*
- [ ] **5.1e** The profile is a **versioned, reviewable, citable artefact**, committed to the repo
- [ ] **5.1f** *Optional, later:* add the **open-source [Azure Quantum Resource Estimator](https://learn.microsoft.com/en-us/azure/quantum/intro-to-resource-estimation)** (`pip install qsharp`, runs locally, has `FactoringFromLogicalCounts`) only for key sizes no paper covers. Qualtran is more rigorous still but is a circuit-construction research tool — overkill for ~20 rows

> **Note — your architecture doc's RSA figure is already superseded.** It cites
> Gidney–Ekerå 2021 (20M noisy qubits); the 2025 paper cuts that to under 1M, a
> ~20× reduction. **Build the first profile from the 2025 figures.** This is not
> a problem with the design — it is the design working: profiles are versioned
> precisely so a new paper becomes `2026.3` and `rescore_all` honestly re-scores
> everything. It is also the single most persuasive thing to show in a demo.

### 5.2 `mosca_engine` — Track A
- [ ] **5.2a** Pure function of `(context, profile)`. No database, no HTTP, no clock reads that matter
- [ ] **5.2b** **Resolving X** from four ranked sources: `EVIDENCE_USER` (high) → `EVIDENCE_SCANNER` data-flow (medium) → `EVIDENCE_ORG_POLICY` (high) → `EVIDENCE_LEGAL_PROFILE` (low)
- [ ] **5.2c** Precedence is strict, and **within the strongest tier that produced anything, the longest lifetime governs** — if an artefact protects both session tokens and health records, the health record decides
- [ ] **5.2d** **Y is user- or organisation-supplied — never inferred.** Trinetra cannot see team capacity, budget cycles or vendor roadmaps
- [ ] **5.2e** Z = configured planning horizon, else M from Track B. **Z records its own basis**: `org_horizon` / `resource_model` / `unavailable`
- [ ] **5.2f** `X + Y > Z` → urgent; compute shortfall in years
- [ ] **5.2g** **When no evidence supports an X, report none. Do not default** *(already enforced by the Phase 1 `MoscaTrack` validator)*

### 5.3 `resource_engine` — Track B
- [ ] **5.3a** Q = logical resources the attack requires, from the 5.1 profile
- [ ] **5.3b** P(t) = projected capability per year 2026–2045: IBM roadmap anchors → interpolated → extrapolated tail
- [ ] **5.3c** Scenario scales P(t): conservative 0.5× · baseline 1× · aggressive 2×
- [ ] **5.3d** **A scenario scales P(t) and never Q.** The attack requirement is a property of the algorithm, not of anyone's roadmap optimism
- [ ] **5.3e** M = first year where `P(t) ≥ Q`, with **both dimensions met** — several curve years publish a gate count but no comparable logical-qubit count, and **half an answer is not an answer**
- [ ] **5.3f** Status: `calculated` / `beyond_horizon` / `model_unavailable` / `not_required`
- [ ] **5.3g** Curve-point confidence maps `roadmap|moderate → medium`, `low → low`. A crossing year **in the extrapolated tail is low confidence by construction**, because the curve itself says so

### 5.4 `final_risk_engine` — combination
Additive, **not averaged** — the tracks are independent evidence about different things.

- [ ] **5.4a** The 100-point scale: quantum vulnerability 25 · Mosca timing 20 · resource feasibility 15 · data sensitivity 12 · business criticality 10 · exposure 10 · migration complexity 8
- [ ] **5.4b** Bands: **≥75 → P0 · 50–74 → P1 · <50 → P2**
- [ ] **5.4c** **Policy short-circuits run first.** An already-broken algorithm (MD5, SHA-1, DES, 3DES), a known quantum-resistant one, or a dependency-only finding is decided by policy and returns **no score**
- [ ] **5.4d** A factor with no evidence contributes **zero and says so** — never a midpoint *(Phase 1 `ScoreContribution` enforces this)*
- [ ] **5.4e** **The score is `None` unless both tracks produced a result** *(Phase 1 `RiskAssessment` enforces this)*
- [ ] **5.4f** Confidence = the **weaker** of the two tracks, dropped one level further when any factor lacked evidence
- [ ] **5.4g** Append a new `risk_assessments` row — never update (P5)

### 5.5 HNDL and classification *(R10, R11)*
- [ ] **5.5a** Flag long-lived sensitive data in transit under classical key exchange
- [ ] **5.5b** **Separate confidentiality risk (retroactive, urgent) from authenticity risk (only matters at CRQC time)** — signatures are a later problem than key exchange, and the tool should say so
- [ ] **5.5c** Classify by type, lifetime and business criticality; criticality inherits down the dependency graph

### 5.6 `rescore_all` — the demoable moment
- [ ] **5.6a** New settings → **new immutable** `org_setting_versions` row, old one deactivated
- [ ] **5.6b** Rebuild each artefact's context **from stored provenance**, re-run `classify_risk` + `recommend_replacement`
- [ ] **5.6c** **Append** a new assessment per artefact; history preserved
- [ ] **5.6d** Return `artefacts_rescored`
- [ ] **5.6e** Because the engines are pure and X, Y and Z were stored, this is a **genuine recalculation, not a relabel** — move the horizon slider, watch every verdict honestly change

### 5.7 Engine tests — pure, so exhaustively testable
No fixtures needed; every one is a plain function call.

- [ ] **5.7a** Missing evidence yields `None`, never a number
- [ ] **5.7b** A factor with no evidence contributes zero **and is labelled**
- [ ] **5.7c** No score unless **both** tracks produced a result
- [ ] **5.7d** Policy short-circuits return no score
- [ ] **5.7e** **Identical inputs → identical outputs** (what makes `rescore_all` real)
- [ ] **5.7f** Confidence is the weaker track, downgraded on missing evidence
- [ ] **5.7g** A capability year missing either dimension cannot satisfy Q
- [ ] **5.7h** A scenario scales P(t) and **never** Q
- [ ] **5.7i** Within the strongest evidence tier, the longest lifetime governs
- [ ] **5.7j** **The §10 worked example reproduces exactly** — RSA-2048, X=8, Y=4, Z=12, Q=6,190 qubits, M=10y, total 58/100, confidence low, P1. This single test catches any regression in the whole combination path

**Exit criteria (vertical slice #2):** the fixture repo produces per-artefact two-track verdicts with full arithmetic stored; the worked example reproduces exactly; changing a profile re-scores everything and appends new history.

---

# PHASE 6 — PQC Recommendation Engine *(R13)*

> **Corrected against §11.** My original 6.3/6.4 would have *modelled* latency and
> cost into a composite fit score. The architecture forbids exactly that:
> *"a universal deployment score cannot be derived from a standard's object
> sizes."* Published FIPS sizes are fact; latency on your hardware is not. So
> unmeasured dimensions are **labelled as unmeasured, never scored.**

*Goal: profile-driven, pure recommendations that separate published fact from
what the team still has to test.*

### 6.1 Scope
- [ ] **6.1a** Runs **only on actionable findings (P0 / P1)** — recommending a fix for an unassessed artefact implies a verdict that was never reached
- [ ] **6.1b** Pure function of `(context, profile)`, like every other engine (P2)

### 6.2 The evidence profile *(schema v2, `nist-pqc-evidence-2026.2`)*
- [ ] **6.2a** Built from **liboqs**: public key, ciphertext and signature sizes per parameter set
- [ ] **6.2b** Every entry cited to **FIPS 203 / 204 / 205**
- [ ] **6.2c** Requires a named `selection_policy` with `required_security_category`
- [ ] **6.2d** **`FitResult.total` is null by design.** `fit_score` is nullable in the database for this reason
- [ ] **6.2e** Schema v1 (`2026.1`, five weighted dimensions summing to 1.0 within 1e-9) retained for **read compatibility only**; new assessments use v2

### 6.3 Mapping, gated by security category
- [ ] **6.3a** RSA / ECC / ECDH / DH / X25519, key exchange → **ML-KEM** (FIPS 203): category 1 → 512, 3 → 768, 5 → 1024
- [ ] **6.3b** RSA / ECC / ECDSA / DSA / Ed25519, signature → **ML-DSA** (FIPS 204): 1 → 44, 3 → 65, 5 → 87
- [ ] **6.3c** Where statelessness is required → **SLH-DSA** (FIPS 205): SHA2-128s / 192s / 256s
- [ ] **6.3d** AES-128 → **AES-256**, direct
- [ ] **6.3e** Hybrid mode pairs the PQC algorithm with a classical partner (`DEFAULT_CLASSICAL_PARTNER = X25519`) when the context calls for it
- [ ] **6.3f** **An unknown algorithm escalates to `MANUAL_REVIEW`** rather than silently scoring 100

### 6.4 Measured, not modelled
- [ ] **6.4a** Publish FIPS object sizes as **fact**, with citation
- [ ] **6.4b** Label latency, protocol compatibility and MTU impact as **unmeasured** — do not model them
- [ ] **6.4c** *Optional and correct:* **benchmark liboqs on the deployment's own hardware**, converting an unmeasured dimension into a measured one. That is the right way to get a latency number — measure it, do not model it
- [ ] **6.4d** The UI shows current vs recommended **side by side with published sizes and cited sources**, and labels unmeasured dimensions as unmeasured (§15 S6)

### 6.5 Migration planning
- [ ] **6.5a** Migration waves sequenced by Mosca deadline and dependency order
- [ ] **6.5b** HSM firmware that is not PQC-capable is a **hardware purchase, not a code change**, and dominates the cost picture — surface it as such
- [ ] **6.5c** Crypto-agility observation: a hardcoded algorithm constant is harder to change again later than a config-driven provider

### 6.6 Tests
- [ ] **6.6a** Every classical algorithm in the profile yields a valid, cited recommendation
- [ ] **6.6b** **An unknown algorithm escalates to manual review** — never a silent fit score of 100
- [ ] **6.6c** No composite confidence score is ever emitted
- [ ] **6.6d** Recommendations are produced for P0/P1 only

**Exit criteria:** every actionable artefact carries a cited, category-gated recommendation, with unmeasured dimensions visibly labelled rather than scored.

---

# PHASE 7 — Standardised Reporting & Export *(R18, R19)*
*Goal: output that other tools and auditors accept.*

- [ ] **7.1** **CycloneDX 1.6 CBOM export** — the standard. `cryptoProperties`: `assetType`, `algorithmProperties` (primitive, parameterSetIdentifier, curve, executionEnvironment, certificationLevel, mode, padding, cryptoFunctions), `certificateProperties`, `relatedCryptoMaterialProperties`, `protocolProperties`. Include `evidence` and `occurrences`. **Validate against the official JSON schema in CI.**
- [ ] **7.2** SPDX 3.0 export (secondary)
- [ ] **7.3** Native JSON export (full fidelity — carries risk and recommendations that the standard format cannot)
- [ ] **7.4** CSV / Excel artefact register for GRC teams
- [ ] **7.5** **Executive PDF report**: posture summary, Mosca timeline, top risks, budget and roadmap — written for a CISO, not an engineer
- [ ] **7.6** **Technical PDF / HTML report**: full inventory with file:line evidence and remediation steps
- [ ] **7.7** SARIF export for CI / code-scanning integration
- [ ] **7.8** Diff reports: scan N vs scan N−1 (what appeared, what was fixed, posture delta)
- [ ] **7.9** Report templating (Jinja2 + WeasyPrint)
- [ ] **7.10** Schema-conformance tests against the published CycloneDX validator

**Exit criteria (vertical slice #3):** `trinetra scan repo X --format cyclonedx` emits a file that passes official CycloneDX validation and contains versions and modes.

---

# PHASE 8 — Backend API & Orchestration
*Goal: turn the library into a service the GUI can drive.*

- [ ] **8.1** FastAPI skeleton, OpenAPI generation, CORS
- [ ] **8.2** AuthN / AuthZ: JWT, roles (admin / analyst / viewer), multi-tenant project scoping
- [ ] **8.3** Scan lifecycle endpoints: `POST /scans`, `GET /scans/{id}`, cancel, list, rescan
- [ ] **8.4** Async worker execution (Celery / RQ) with **progress reporting** — a ten-minute scan with no feedback is unusable
- [ ] **8.5** WebSocket / SSE live scan progress and log stream — **must emit percentage, current stage and running counts**, not just "running", because §4.5a depends on it
- [ ] **8.6** Artefact query API: filter by type / risk / app / algorithm, paginate, sort, full-text search
  - [ ] **Facet counts returned with results** so the UI can show "Critical (42)" beside each filter *(§4.2, orientation before drill-down)*
  - [ ] **Partial/streaming results available while a scan is still running** *(§4.5b)*
  - [ ] Server-side default sort = risk descending *(§4.2e)*
- [ ] **8.7** Risk and Mosca endpoints, including **what-if recalculation** when Z or X changes — must be fast, because it drives a UI slider
- [ ] **8.8** Recommendation endpoints
- [ ] **8.9** Export endpoints (all Phase 7 formats)
- [ ] **8.10** Asset / application CRUD (criticality, data classification, owner)
- [ ] **8.11** Settings API: Mosca defaults, risk weights, rule-pack toggles
- [ ] **8.12** Persistence layer + historical scan retention for trend analysis
- [ ] **8.13** Rate limiting, request validation, audit log of every action
- [ ] **8.14** API integration tests

**Exit criteria:** a UI-ready OpenAPI spec; a scan can be started, watched and queried over HTTP.

---

# PHASE 9 — Interactive GUI: Core *(R20, R21)*
*Goal: the interactive visualisation platform the deliverable demands — and one a non-expert can actually use.*
*Every task below is bound by the §4 UX Doctrine.*

### 9.0 Design before code *(do not skip — this is what prevents a rebuild)*
- [ ] **9.0a** **Wireframe the four core screens first** (Dashboard, Scan progress, CBOM Explorer, Artefact detail) — on paper or in Figma, before any React is written
- [ ] **9.0b** Map each screen to its persona from §4.1 and write the "10-second question" it answers at the top of the spec
- [ ] **9.0c** Walk the three personas through the wireframes; fix confusion on paper, where it is free
- [ ] **9.0d** Define the **design tokens** up front: risk colour scale, spacing, type scale, asset-type icon set — so §4.8 consistency is structural, not a later cleanup

### 9.1–9.3 Foundation
- [ ] **9.1** React + TS + Vite scaffold; TanStack Query; typed client generated from OpenAPI
- [ ] **9.2** **Design system** implementing §4.8: layout shell, persistent left nav, breadcrumbs, light/dark theme, component library (table, badge, drawer, chart frame, tooltip, empty state, skeleton), and the **single shared risk colour scale**
- [ ] **9.3** Auth flow, protected routes, **role-based default landing page** *(§4.1b)*

### 9.4 Dashboard / posture overview — *the executive screen*
- [ ] **9.4a** **At most 5 headline tiles** *(§4.2b)*: total artefacts, quantum-vulnerable count, critical risks, % quantum-safe, nearest Mosca deadline
- [ ] **9.4b** **"Top 5 things to fix this quarter" panel** *(§4.4c)* — plain language, each row one click from the evidence
- [ ] **9.4c** Risk-distribution donut and artefact-type breakdown, each drilling through to a filtered Explorer view
- [ ] **9.4d** Top-10 at-risk applications
- [ ] **9.4e** Posture trend over time
- [ ] **9.4f** Every tile states **what it means in one plain sentence** on hover *(§4.3a)*
- [ ] **9.4g** Readable by a non-technical executive with **zero clicks and no training** — the acceptance test for this screen

### 9.5 Scan management — *never leave the user staring at nothing (§4.5)*
- [ ] **9.5a** New-scan wizard: target type (repo / binary / image / host / cloud), configure, launch — **launchable by filling one field** thanks to sane defaults *(§4.11d)*
- [ ] **9.5b** **Live progress: real percentage + current stage + file counts**, streamed *(§4.5a)*
- [ ] **9.5c** **Partial results stream into the table during the scan** *(§4.5b)*
- [ ] **9.5d** Collapsible live log for users who want it; hidden by default *(§4.2c)*
- [ ] **9.5e** Scan history and diff-against-previous
- [ ] **9.5f** Actionable error states with the cause and the fix *(§4.5e)*

### 9.6 CBOM Explorer — *the analyst's main working surface*
- [ ] **9.6a** Virtualised artefact table, smooth at **100k rows** *(§4.10a)*
- [ ] **9.6b** **Opens sorted by risk, descending, with a default column set** — the worst finding is the first row *(§4.2d, §4.2e)*
- [ ] **9.6c** Faceted filters with live result counts: asset type, algorithm, risk band, application, quantum status, library
- [ ] **9.6d** Column selection, sort, saved views; **filter state lives in the URL** *(§4.7c)*
- [ ] **9.6e** **Artefact detail drawer** — the trust-builder *(§4.6)*:
  - [ ] Plain-English summary sentence at the top, before any jargon *(§4.3b)*
  - [ ] **Syntax-highlighted code evidence at file:line**
  - [ ] Mosca breakdown **showing X, Y, Z and the arithmetic** *(§4.6c)*
  - [ ] Recommendation with rationale, latency and cost
  - [ ] Confidence level and detection method, shown openly *(§4.6b)*
  - [ ] A clear primary action button *(§4.4a)*
- [ ] **9.6f** Bulk actions: accept risk, assign owner, mark false positive (with reason, and it sticks across rescans — §4.6e)
- [ ] **9.6g** **Coverage-gap banner** when the scan could not see everything *(§4.6d)*

### 9.7–9.9 Cross-cutting
- [ ] **9.7** Global search (`/` or `Ctrl-K`) across applications, algorithms and artefacts *(§4.7e)*
- [ ] **9.8** Export buttons wired to every Phase 7 format, with format explanations in plain language
- [ ] **9.9** **Glossary page + inline `ⓘ` tooltips** for every acronym *(§4.3a, §4.3c)*

**Exit criteria:** a user can launch a scan, watch it progress, explore results, open evidence and download a CBOM without touching the CLI **and without being told how** — verified by §10B usability testing, not by the builder's own opinion.

---

# PHASE 10 — Interactive GUI: Risk & Migration Visualisation *(R9–R13 made visible)*
*Goal: the screens that show this is a risk platform, not an inventory list.*

- [ ] **10.1** **Mosca timeline visualiser** — a horizontal timeline per system: X bar, Y bar, Z marker, with the overshoot region in red. **Interactive Z slider (2030 / 2035 / 2040 / custom) that recalculates live.** *This is the single most important screen in the product — it makes an abstract inequality legible at a glance.*
- [ ] **10.2** Risk heatmap: business criticality × quantum vulnerability, cells drilling through to artefacts
- [ ] **10.3** **Crypto dependency graph** (Cytoscape): application → library → algorithm, coloured by risk; click a node to see its blast radius. Answers "if OpenSSL is the problem, what breaks?"
- [ ] **10.4** **HNDL exposure view**: externally exposed + long-lived data + classical KEX — the "act this quarter" list
- [ ] **10.5** Certificate lifecycle view: expiry calendar, signature-algorithm distribution, chains with quantum-vulnerable roots
- [ ] **10.6** **Algorithm inventory view**: usage frequency per algorithm / mode / key size, with vulnerable ones surfaced
- [ ] **10.7** **Migration planner**: roadmap Gantt by wave, effort and cost rollups, drag-to-reprioritise, planned date vs Mosca breach date
- [ ] **10.8** **Recommendation workspace**: current vs proposed side by side, latency / size / cost deltas charted, accept → generates a remediation ticket
- [ ] **10.9** **What-if simulator**: "if we migrate these 10 systems, posture goes from X to Y" — turns the tool into a planning instrument
- [ ] **10.10** Compliance dashboard: CNSA 2.0 / NIST IR 8547 deadline tracking
- [ ] **10.11** In-app report preview and download
- [ ] **10.12** **Every visualisation above carries a `?` "how to read this chart" explainer** *(§4.11c)* — a heatmap or dependency graph is useless to someone who cannot decode it
- [ ] **10.13** Every chart has an accessible text alternative and an underlying data table *(§4.9e)*
- [ ] **10.14** Every drill-down path is URL-addressable and breadcrumbed *(§4.7b, §4.7c)*

**Exit criteria:** every requirement R9–R13 is visible and interactive on screen — and a first-time viewer can explain what each screen means.

---

# PHASE 10B — Usability Validation & Accessibility *(R21 — the gate on the GUI)*
*Goal: prove the UI is easy, rather than assume it. **This phase is what turns §4 from aspiration into fact.***

- [ ] **10B.1** **Usability testing with 5 real people** — ideally one executive, two analysts, two developers. Five testers surface the large majority of usability problems; this is the highest-value item in the phase
  - [ ] Give **tasks, not tours**: "Find the riskiest system and tell me why it's risky." "Find out what to replace its algorithm with." "Show me the evidence this finding is real."
  - [ ] **Observe silently.** Record where they hesitate, misread a label, or click the wrong thing
  - [ ] Log every point of confusion as a bug — *confusion is a defect, not a user error*
- [ ] **10B.2** Fix the issues found, then **re-test the same tasks** to confirm the fix worked
- [ ] **10B.3** **First-run guided tour** of the four core screens, skippable and re-runnable *(§4.11a)*
- [ ] **10B.4** **One-click demo dataset** so the product is never first seen empty *(§4.11b)*
- [ ] **10B.5** **Accessibility audit** *(§4.9)*: axe/Lighthouse automated pass, then manual keyboard-only walkthrough of all four core flows, then a screen-reader pass
- [ ] **10B.6** **Colour-blind simulation check** on every risk visualisation — verify meaning survives with colour removed *(§4.9b)*
- [ ] **10B.7** Responsive layout verified at laptop, small-laptop and tablet widths
- [ ] **10B.8** Plain-language sweep: read every label, tooltip and error message aloud; replace anything that needs a cryptographer to parse *(§4.3)*
- [ ] **10B.9** Performance verification against §4.10 targets with a realistic 100k-artefact dataset
- [ ] **10B.10** **Full §4 checklist audit** — walk §4.1 to §4.11 and tick each item against the built product

**Exit criteria:** five testers complete the core tasks unaided; the §4 checklist is fully ticked; accessibility audit passes.

---

# PHASE 11 — Integration, Hardening & Scale

- [ ] **11.1** End-to-end tests: scan → risk → recommend → export → UI render
- [ ] **11.2** Performance: large monorepo (>1M LOC) and large images; parallel workers; incremental rescan
- [ ] **11.3** Caching (artefact-hash based) so rescans are fast
- [ ] **11.4** **Accuracy benchmark**: precision / recall against the labelled fixture corpus, published in the docs — *a scanner that cannot state its false-positive rate cannot be trusted*
- [ ] **11.5** **Security of the tool itself**: it handles keys and cloud credentials — secrets never logged, evidence snippets redacted where they contain key material, encryption at rest, least-privilege cloud roles
- [ ] **11.6** CI/CD integration mode: `trinetra scan --fail-on critical` as a pipeline gate, plus SARIF upload
- [ ] **11.7** Error resilience: one malformed file must never kill a scan
- [ ] **11.8** Observability: metrics, traces, health endpoints
- [ ] **11.9** Deployment: Docker Compose (demo) + optional Helm chart

---

# PHASE 11A — Coverage Extension: Live TLS *(testssl.sh · §7.4)*

> **Moved here from the original Phase 4.** The architecture calls this *"the
> highest-value extension"* but explicitly not core: it needs outbound network
> access, which is a different blast radius, so it is **a fourth scanner
> service** on `scanner-egress` rather than an addition to an existing one.

*Answers the question no other scanner in the stack can: what is actually
negotiated on a live port.* Source code says what a service intends; an image
says what is installed. Neither tells you a load balancer in front still accepts
TLS 1.0, or that the certificate is RSA-2048 regardless of what the application
configures.

- [ ] **11A.1** Fourth Go service on `scanner-egress`, same `cbom-go` contract
- [ ] **11A.2** testssl.sh adapter: protocol versions, cipher suites, cert key types on a live endpoint
- [ ] **11A.3** Emit `protocol` artefacts with **`is_observed=true`** — the Phase 1 schema already distinguishes observed from declared, and that distinction must reach the UI
- [ ] **11A.4** Detect hybrid PQC KEX (`X25519MLKEM768`); flag TLS 1.0/1.1 and RSA key transport
- [ ] **11A.5** SSH host-key / KEX / MAC enumeration
- [ ] **11A.6** **Observed-vs-declared diff view** — the widest coverage gain in the product, and the finding a customer is most likely to act on immediately

---

# PHASE 11B — Coverage Extension: Binaries, CVEs, NER PII *(§7.4)*

> **Moved here from the original Phase 3.** LIEF/Ghidra binary analysis was core
> in my first plan; the architecture places it last, on its own queue, because it
> is slow and its blast radius differs again.

- [ ] **11B.1** **Ghidra** on its own queue: crypto constants and API calls in stripped binaries (AES S-box, SHA-256 IV, MD5 table, DES S-boxes)
- [ ] **11B.2** ELF / PE / Mach-O symbol and linked-library extraction
- [ ] **11B.3** Java `.jar`/`.war` constant-pool inspection; .NET assembly metadata
- [ ] **11B.4** **OSV-Scanner**: CVE data per package — *present-tense* risk shown alongside the future quantum verdict, clearly separated so the two are never confused
- [ ] **11B.5** **Presidio**: NER-based sensitive-data classification, strengthening the X evidence tier beyond regex
- [ ] **11B.6** Each remains an **evidence source, never a verdict source** (§7.1)

---

# PHASE 12 — Documentation & Delivery

- [ ] **12.1** `README` — problem, solution, quickstart, screenshots
- [ ] **12.2** Architecture doc (**fill in `full architecher.md`**)
- [ ] **12.3** **Methodology whitepaper**: the Mosca implementation, the risk formula, the Z assumptions, algorithm KB sources — the credibility document
- [ ] **12.4** User guide + API documentation
  - [ ] **Written so it is optional, not required** — if the UI needs the manual to operate, §4 has failed and the UI gets fixed instead
- [ ] **12.5** Rule-pack authoring guide (extending detection without writing code)
- [ ] **12.5b** **Design-system / UX guide**: the §4 doctrine, design tokens, component usage — so later screens stay consistent with the built ones
- [ ] **12.6** Sample CBOM reports committed as examples
- [ ] **12.7** Demo script + seeded demo dataset
- [ ] **12.8** Demo video / walkthrough
- [ ] **12.9** **Final requirement-coverage audit** — re-verify the §1 table; every row checked

---

## 5. Milestones

| M | Name | Phases | Demonstrable outcome | Status |
|---|---|---|---|---|
| **M1** | Foundation | 0, 1 | Repo runs; contract frozen | **done** (161 py tests) |
| **M1B** | The wire contract | 2.0, 2.1 | Go and Python agree byte-for-byte on one CBOM shape | **done** |
| **M2** | It finds crypto | 2 | Scanner writes a schema-valid CBOM; ingest populates `artefacts`; 100%/100% on the corpus | **done** |
| **M3** | It finds crypto everywhere | 3, 4 | Containers, certs, keys, libraries, HSM, KMS | |
| **M4** | **It assesses quantum risk** | 5 | Two-track verdicts; the §10 worked example reproduces exactly | |
| **M5** | It tells you what to do | 6 | PQC recommendations, FIPS-cited, unmeasured dimensions labelled | |
| **M6** | It produces standard reports | 7 | Valid CycloneDX CBOM + executive PDF | |
| **M7** | It has a GUI | 8, 9 | Full scan-to-explore workflow in the browser | |
| **M8** | It visualises risk | 10 | Mosca timeline, heatmap, dependency graph, planner | |
| **M8B** | **It is genuinely easy to use** | 10B | 5 testers complete the core tasks unaided; accessibility audit passes | |
| **M9** | It is production-ready | 11, 12 | Benchmarked, documented, deployable | |
| **M10** | Wider coverage | 11A, 11B | Live TLS, binaries, CVEs, NER PII | |

> **The architecture's own definition of the minimum viable platform** (§7.7):
> the CBOM contract, Semgrep, the Q capability profile, and liboqs — i.e. M1B
> through M5. *"Everything after that widens coverage without changing the
> architecture — which is the test of whether the architecture is right."*

### Build vs adopt — the boundary
> **Adopt everything that is inventory. Build everything that is judgement.**

| | Source |
|---|---|
| **Adopted** — detection, parsing, inventory, PQC parameters, Q values | PQCA CBOMkit · cbomkit-theia · Semgrep · Syft · liboqs · cited papers |
| **Built** — *this is the product* | Two-track risk engine · Mosca · quantum-resource model · versioned policy profiles · context/provenance chain · PQC recommendation gating · PII→crypto taint rules · the entire UI |

No existing open-source tool does the built column. CBOMkit stops at inventory
plus an allowlist check; that is precisely where Trinetra starts. **Saving ~3–4
weeks on Phases 2–3 buys that time for Phase 5, which is the part a screenshot
cannot show and a competitor cannot copy.**

---

## 6. Priority Tiers (if time gets constrained)

**P0 — cannot ship without (this *is* the problem statement):**
Phases 0, 1, **2.0–2.1 (contract + CBOMkit evaluation)**, 2, **2.3 (taint rules — Mosca's X depends on them)**, 5, 6, 7, 8, 9 (including **9.0 wireframing**), tasks 10.1–10.4, and **10B.1, 10B.2, 10B.4, 10B.8** (usability test, fix, demo data, plain-language sweep)

**P1 — strongly expected:**
Phase 3 (containers and libraries are named explicitly in the deliverable), tasks 10.5–10.8, remaining 10B items, 12.1–12.3

**P2 — differentiators:**
Phase 4 (cloud / HSM), **Phase 11A (live TLS — the highest-value coverage extension)**, tasks 10.9–10.10, 11.4, 11.6

**P3 — polish and wider coverage:**
Phase 11B (binaries, CVE, NER), the remainder of Phases 11 and 12

> **If the schedule slips, cut scanner *breadth* (fewer languages, skip cloud connectors) before cutting risk *depth*. A tool that inventories five languages and reasons rigorously about quantum risk answers this problem statement. A tool that inventories twelve languages and shows a risk badge does not.**
>
> **Usability is not in the cuttable category either.** §4 items are cheap when designed in (9.0) and expensive when retrofitted. Ten extra artefact-table columns are worth less than one tooltip that makes "Mosca deficit" comprehensible — because an unusable risk platform gets abandoned no matter how accurate its engine is.

---

## 7. Risks to the Build

| Risk | Mitigation |
|---|---|
| False positives destroy trust | AST layer over regex (2.4); confidence scores; measured precision/recall (11.4); suppression (2.11) |
| Mosca inputs (X, Y, Z) are guesses | Make them explicit, configurable and auditable; ship scenario sliders rather than one hidden number |
| Scanner breadth eats the whole schedule | Rule-packs as data (2.2); timebox per language; cut breadth, not depth |
| Stripped / statically linked binaries hide crypto | Constant signatures (3.1); state coverage limits honestly in the report |
| CycloneDX CBOM spec drift | Pin 1.6; validate in CI (7.10) |
| Building UI before the data shape settles | Phase 1 freezes the schema; typed client generated from OpenAPI |
| **The two vocabulary tables (`vocab.go` / `vocab.py`) drift apart** | A shared fixture drives round-trip tests on **both** sides (2.1d); they must be exact inverses |
| **A Semgrep rule forgets message interpolation and silently loses the key size** | Now only affects the *narrow* gap pack (2.4); a lint test enforces both constraints mechanically |
| **Adopting CBOMkit imports its false positives as ours** | Measure precision/recall on our own corpus (2.1a, 2.7e) — adoption does not transfer responsibility |
| **An upstream tool changes behaviour on upgrade** | Pin exact versions, vendor artefacts, golden-CBOM diffs reviewed not regenerated |
| **CBOMkit's language coverage is narrower than the plan claimed** | Java/Python/Go only. Either fill JS/TS + C/C++ with a small pack (2.4) or **declare them out of scope and show it in coverage stats** — an honest gap beats a weak rule pack |
| **A vendored tool cannot be fetched in an air-gapped install** | Vendor/mirror every binary and jar as a release artefact (2.1d, 3.1c) |
| **A library finding manufactures an attack model from a package name** | Enforced three times: Pydantic validator, DB CHECK constraint, and the ingest mapping |
| **Q drifts with roadmap optimism** | A scenario scales P(t) and never Q (5.3d), asserted as a test |
| **Binary scanning (R15) never ships because it is last** | Flagged above as an explicit decision, not a schedule outcome |
| The tool itself becomes a secret-leak vector | 11.5 — redaction, encryption, least privilege |
| **UI overwhelms the user — 100k artefacts dumped on one screen** | §4.2 progressive disclosure; risk-sorted defaults; three-layer depth |
| **Jargon makes the tool unusable for non-cryptographers** | §4.3 plain-language rules; tooltips on every acronym; glossary; 10B.8 sweep |
| **"It's obvious to me" — the builder cannot judge their own UI** | 10B.1 testing with 5 real users; confusion logged as a defect, not user error |
| **UX deferred to the end, then cut when time runs out** | 9.0 wireframes precede coding; §4 items are embedded in 9.x/10.x tasks, not a separate backlog |

---

## 8. Working Conventions

- Tick a box **only** when the code is merged, tested, and the vertical slice still runs end to end.
- Every phase from 2 onward ends with a runnable demo, not just green unit tests.
- Every detection rule is data (`crypto-rules.yml`), never a hardcoded branch — and every rule matches a **call expression**, never a bare identifier.
- Every upstream tool is **a source of evidence, never a source of verdicts** (§7.1). Wrap, never fork; the adapter is the trust boundary; a tool's vocabulary never leaks inward.
- Engines are **pure functions of `(context, profile)`** — no database, no HTTP, no clock reads that matter. This is what makes `rescore_all` a real recalculation rather than a relabel.
- Profiles are **versioned and cite their sources**; a malformed profile fails **at load, not at scoring time**.
- Every risk verdict stores its inputs and is reproducible.
- Every artefact carries evidence (file, line, snippet) — an unsourced finding is a bug.
- Anything the scanner *cannot* see is stated in the report as a coverage gap, never silently omitted.

**UI-specific conventions (§4 enforcement):**

- **No UI screen is "done" until it passes its §4 checks** — persona named, plain-language summary present, primary action present, keyboard-operable.
- **A confused user is a bug report, not a training problem.** If a tester hesitates, fix the screen.
- **No jargon ships without a tooltip.** If a term needs a cryptography background to parse, it needs an `ⓘ`.
- **No number ships without meaning.** A score of 78 with no explanation is noise.
- **Wireframe before code** — every new screen gets sketched and persona-checked first (9.0).
- **Colour never carries meaning alone** — always colour + label + icon.
- **Test with a full dataset, never 10 rows.** Layouts that work at 10 artefacts break at 10,000; use the demo dataset (10B.4) for all UI development.
