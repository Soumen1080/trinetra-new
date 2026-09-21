# Trinetra — Post-Quantum Cryptography (PQC) Migration & Risk Platform

Trinetra is an automated **Cryptographic Bill of Materials (CBOM)** discovery and **Post-Quantum Cryptography (PQC) Risk Assessment** platform. It analyzes source code and infrastructure to find legacy cryptography (e.g., RSA, ECC, 3DES), evaluates quantum threats (Shor's and Grover's algorithms), models Mosca's inequality ($X + Y > Z$), and provides NIST-aligned migration roadmaps.

---

## 🚀 Quick Start (Running with Docker)

The entire platform runs in Docker Compose with 5 microservices:
- **`trinetra-frontend`**: React + Vite UI running on [http://localhost:3000](http://localhost:3000)
- **`trinetra-backend`**: FastAPI REST & WebSocket API on [http://localhost:8000](http://localhost:8000)
- **`trinetra-worker`**: Celery asynchronous scan task runner
- **`trinetra-scanner-source`**: Go-based CBOM discovery engine using Semgrep crypto rules
- **`trinetra-redis`**: Celery broker and cache

### 1. Launch Containers
```bash
docker compose up -d
```

### 2. Access the Platform
- **URL**: [http://localhost:3000](http://localhost:3000)
- **Default Credentials**:
  - **Username**: `admin`
  - **Password**: `adminpassword`

---

## 🧭 How to Use & What Results You Get

### 1. Overview Dashboard (`/dashboard`)
* **What you see**: High-level posture summary of your project.
* **Results displayed**:
  - **Quantum-Vulnerable Findings Count**: Algorithms vulnerable to quantum attacks (Shor / Grover).
  - **Quantum-Safe Percentage**: Percentage of discovered assets that already meet quantum-safe standards.
  - **Nearest Mosca Deadline**: The most critical deadline before Harvest Now, Decrypt Later (HNDL) becomes a threat.
  - **Priority Breakdown**: Findings grouped by P0 (Immediate), P1 (High), P2 (Medium), and None.
  - **Worst Offenders Table**: Top 5 critical cryptographic weaknesses with recommendations.

### 2. Cryptographic Explorer (`/explorer`)
* **What you see**: A searchable, filterable inventory of every cryptographic asset discovered across scans.
* **Results displayed**:
  - **Algorithm & Key Size**: (e.g., `RSA-2048`, `ECDH-P256`, `AES-256-GCM`, `SHA-1`).
  - **Quantum Status Badge**:
    - `🔴 Shor Broken`: Asymmetric encryption & signatures that Shor's algorithm will completely break (e.g., RSA, ECC, Diffie-Hellman).
    - `🟡 Grover Weakened`: Symmetric ciphers and hashes with halved effective security (e.g., AES-128, 3DES).
    - `🟢 Quantum Safe`: Post-quantum algorithms (e.g., ML-KEM, ML-DSA) or 256-bit symmetric ciphers.
    - `⛔ Classically Broken`: Algorithms already vulnerable to classical attacks (e.g., MD5, SHA-1, DES).
  - **Code Location**: Exact file path and line number where the algorithm or key is initialized.
  - **Asset Drawer**: Clicking any finding opens detailed parameters, evidence snippets, and replacement guidance.
  - **CSV Export**: Click **Export CSV** to download the complete raw inventory.

### 3. Scanning a Real Git Repository (`/scans`)
* **How to test a real repository**:
  1. Go to **Scans** in the sidebar.
  2. Click **New Scan**.
  3. Select **Git Repository**.
  4. Enter a public Git URL (e.g. `https://github.com/bottlepy/bottle.git` or your own repository).
  5. Enter a Branch/Tag/Commit (e.g., `master` or `main`).
  6. Click **Launch Scan**.
* **Results displayed**:
  - Real-time progress bar tracking clone, engine analysis, and CBOM ingestion.
  - Automatic extraction of crypto calls, key lengths, cipher modes, and imports.
  - Click the finished scan to view findings and download the generated **CycloneDX 1.6 CBOM** file.

### 4. Interactive Risk Visualisations (`/risk-visualisation`)
* **Mosca Inequality Timeline**:
  - Visualizes **$X + Y > Z$**:
    - **$X$ (Data Life)**: How many years the data must stay secret (e.g., 7–10 years for health/financial data).
    - **$Z$ (Migration Time)**: How many years it will take engineering to migrate to PQC (e.g., 2–3 years).
    - **$Y$ (Quantum Horizon)**: When quantum computers can break the crypto (scenario slider for 2030, 2035, 2040).
  - **Red Overshoot Zone**: Highlights systems that must start migrating immediately because $X + Z > Y$.
* **Risk Heatmap ($5 \times 5$)**:
  - Cross-references **Business Criticality** (None to Critical) against **Quantum Vulnerability**.
  - Clicking any cell filters the Explorer to findings matching that risk intersection.
* **Crypto Dependency Graph**:
  - Interactive DAG rendering `Application ➔ Libraries ➔ Algorithms`.
  - Color-coded risk badges with blast radius analysis.
* **Harvest Now, Decrypt Later (HNDL)**:
  - Filters findings to only those storing long-retention confidential data encrypted with quantum-breakable key exchange.
* **Algorithm Inventory**:
  - Aggregates algorithms by key size and cipher mode with quantum-safety indicators.

### 5. PQC Migration & Remediation (`/migration`)
* **Side-by-Side NIST Recommendations**:
  - Replaces classical algorithms with FIPS 203/204/205 standards (e.g., RSA-2048 $\to$ ML-KEM-768 / X25519MLKEM768).
  - Radar chart showing trade-offs across ciphertext size, public key size, CPU overhead, and implementation maturity.
* **What-If Posture Simulator**:
  - Interactive slider to test different Q-Day timeline scenarios and watch risk scores adjust in real time.
* **Compliance Dashboard**:
  - Tracks posture against government mandates:
    - **CNSA 2.0 Phase 1 (2026)**: Software & firmware code signing.
    - **CNSA 2.0 Phase 2 (2030)**: Web browsers, TLS, and cloud infrastructure.
    - **CNSA 2.0 Phase 3 (2033)**: Core networking and storage encryption.
    - **BSI TR-02102 (2035)**: Absolute legacy cutoff.
* **Reports Generator**:
  - Executive Briefing, Technical Audit, and CycloneDX CBOM report previews with PDF/HTML download.

### 6. One-Click Demo Dataset
If you don't have a repository ready to scan, click the **⚡ Load Demo Dataset** button in the header or on the Overview page. This immediately populates the active project with 48 realistic enterprise findings across 6 applications (Payment Gateway, Auth Service, Edge TLS, Archive, B2B Dispatcher, and HSM).

---

## 🔍 What Works Currently vs. Platform Limitations

### ✅ What is Fully Functional & Tested
1. **Real Git Repository Scanning**: Public Git repositories clone cleanly via HTTPS, preserve your requested branch/tag/commit SHA, generate immutable CBOMs, and extract cryptographic call sites.
2. **Local Path Scanning**: Scanning paths mounted in the container (e.g. `/host-projects/...`).
3. **Quantum Vulnerability Classification**: Automatically classifies `shor_broken`, `grover_weakened`, `classically_broken`, and `quantum_safe` based on NIST and policy profiles.
4. **All Risk Endpoints**: Mosca timelines, 5x5 heatmap, dependency DAG, HNDL filter, compliance tracking, and algorithm inventories return live project-scoped data.
5. **Project Multi-Tenancy**: Scans, applications, and findings are strictly isolated to the active project.
6. **Demo Seeding & Reset**: Creates and cleans real database rows with one click.
7. **Observed vs. Declared Protocol Analysis**: Compares live observed TLS/SSH traffic against declared configs.

### ⚠️ Current Limitations & Potential Faults

| Limitation / Fault | Why it Occurs | Workaround / How to Handle |
| :--- | :--- | :--- |
| **Private Git Repositories (SSH / Private HTTPS)** | Git clone runs inside the worker container without your host SSH keys or GitHub OAuth tokens. | Use public repository URLs, embed a token in the URL (`https://<token>@github.com/...`), or mount your repo folder as a local path. |
| **Non-Source Scanners (Container, Binary, Cloud HSM)** | The Docker Compose topology currently runs `scanner-source`. Container image, binary disassembly, and AWS KMS scanners are separate microservices. | Choose **Git Repository** or **Local Path** when creating a scan in the UI. |
| **Unassigned Applications on Fresh Scans** | A newly scanned Git repo does not automatically belong to a predefined Application entity in Trinetra. | Go to **Applications** and create an application, or findings will display under "Unassigned Findings" until tagged. |
| **Large Repositories (> 500 MB)** | Shallow clone depth is set to 1 by default, but Semgrep AST scanning on massive monorepos can take several minutes. | Scan specific sub-folders or smaller repositories for demonstration. |

---

## 🛠️ Development & Testing

### Running Tests Inside Docker
```bash
# Run backend test suite (299 tests)
docker exec trinetra-backend pytest /host-projects/trinetra-new/backend/tests

# Run frontend test suite (23 tests)
cd frontend && npm test

# Build frontend production bundle
cd frontend && npm run build
```
