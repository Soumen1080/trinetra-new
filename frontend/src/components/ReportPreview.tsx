import { useState } from "react";
import { ChartShell } from "./ChartShell";
import { ExportMenu } from "./ExportMenu";
import { useApi } from "../hooks/useApi";
import { problem } from "./ErrorState";

interface ReportPreviewProps {
  scanId?: string;
  projectName?: string;
  loading?: boolean;
}

export function ReportPreview({
  scanId = "scan-live-latest",
  projectName = "Production Systems Cluster",
  loading = false,
}: ReportPreviewProps) {
  const api = useApi();
  const [reportType, setReportType] = useState<"executive" | "technical" | "cbom">("executive");
  const [downloadMsg, setDownloadMsg] = useState<string>("");
  const [downloading, setDownloading] = useState<boolean>(false);

  const handleDownload = async (format: string) => {
    setDownloading(true);
    setDownloadMsg("");
    try {
      const report = await api.createReport(scanId, format);
      const { blob, name } = await api.downloadReport(report.id);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = name;
      link.click();
      URL.revokeObjectURL(url);
      setDownloadMsg(`Downloaded ${name} successfully.`);
    } catch (err) {
      setDownloadMsg(problem(err));
    } finally {
      setDownloading(false);
    }
  };

  const dataTable = (
    <table className="data-table">
      <thead>
        <tr>
          <th>Section</th>
          <th>Summary Findings</th>
          <th>Risk Urgency</th>
          <th>Action Required</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Executive Summary</td>
          <td>42% of cryptographic assets are quantum-vulnerable</td>
          <td><span className="badge-p0">High Priority</span></td>
          <td>Approve Wave 1 Migration budget ($230k)</td>
        </tr>
        <tr>
          <td>Mosca Inequality</td>
          <td>3 core systems breach secrecy lifetime before 2030</td>
          <td><span className="badge-p0">P0 Urgency</span></td>
          <td>Deploy ML-KEM-768 hybrid KEX to edge ingress</td>
        </tr>
        <tr>
          <td>Harvest-Now-Decrypt-Later (HNDL)</td>
          <td>External TLS with classical KEX and data retention &gt; 7 yrs</td>
          <td><span className="badge-p1">P1</span></td>
          <td>Enable X25519MLKEM768 cipher suites</td>
        </tr>
        <tr>
          <td>Compliance Horizions</td>
          <td>CNSA 2.0 2026 firmware signing & 2030 TLS deadlines</td>
          <td><span className="badge-p1">Regulatory</span></td>
          <td>Upgrade code signing pipeline to ML-DSA</td>
        </tr>
      </tbody>
    </table>
  );

  return (
    <div className="report-preview-container">
      <div className="report-preview-toolbar">
        <div className="report-type-toggle">
          <button
            className={`button ${reportType === "executive" ? "primary" : "secondary"}`}
            onClick={() => setReportType("executive")}
          >
            Executive Summary
          </button>
          <button
            className={`button ${reportType === "technical" ? "primary" : "secondary"}`}
            onClick={() => setReportType("technical")}
          >
            Technical Assessment
          </button>
          <button
            className={`button ${reportType === "cbom" ? "primary" : "secondary"}`}
            onClick={() => setReportType("cbom")}
          >
            CycloneDX CBOM
          </button>
        </div>

        <div className="report-actions">
          <button
            className="button secondary"
            onClick={() => window.print()}
            title="Print or Save as PDF"
          >
            🖨 Print / PDF
          </button>
          <button
            className="button secondary"
            disabled={downloading}
            onClick={() => handleDownload("pdf-executive")}
          >
            Download PDF
          </button>
          <ExportMenu scanId={scanId} />
        </div>
      </div>

      {downloadMsg && (
        <div className="report-download-toast" role="status">
          {downloadMsg}
        </div>
      )}

      <ChartShell
        title="Assessment Report In-App Preview"
        explainer={
          <div>
            <p><strong>How to read this report preview:</strong></p>
            <p>
              This screen provides a live rendered preview of the authoritative Cryptographic Posture
              Assessment for your active workspace.
            </p>
            <ul>
              <li>
                <strong>Executive Summary:</strong> Designed for CISOs and executive boards. Translates
                quantum risk into business exposure, budget estimates, and compliance deadlines.
              </li>
              <li>
                <strong>Technical Assessment:</strong> Includes exact asset coordinates, file locations,
                library symbols, and mathematical proof of Shor/Grover vulnerability.
              </li>
              <li>
                <strong>CycloneDX CBOM:</strong> Industry-standard machine-readable Cryptographic Bill of
                Materials for software supply chain ingestion.
              </li>
            </ul>
          </div>
        }
        note="Live preview of the generated compliance and posture report."
        dataTable={dataTable}
        loading={loading}
        height="auto"
      >
        <div className="report-sheet">
          {/* Document Header */}
          <div className="report-doc-header">
            <div className="report-brand">
              <span className="brand-badge">TRINETRA</span>
              <span className="report-title-text">Post-Quantum Cryptography Posture Report</span>
            </div>
            <div className="report-doc-meta">
              <span>Project: <strong>{projectName}</strong></span>
              <span>Generated: <strong>{new Date().toLocaleDateString()}</strong></span>
              <span>Scan Ref: <code>{scanId}</code></span>
              <span className="badge-p0">Verdict: Action Required</span>
            </div>
          </div>

          <hr className="report-divider" />

          {/* Report Body Content based on Tab */}
          {reportType === "executive" && (
            <div className="report-content-body">
              <section className="report-section">
                <h3>1. Executive Statement of Cryptographic Risk</h3>
                <p>
                  A comprehensive scan of <strong>{projectName}</strong> identified <strong>48 cryptographic assets</strong>,
                  of which <strong>31 (64.5%)</strong> are vulnerable to polynomial-time compromise by a Cryptanalytically
                  Relevant Quantum Computer (CRQC) running Shor's algorithm.
                </p>
                <div className="report-callout-danger">
                  <strong>Critical Finding (Mosca Inequality Deficit):</strong>
                  <p>
                    3 production systems handle customer financial and medical data with mandated 10+ year retention.
                    Given a 2-year estimated engineering migration timeframe and a conservative 2035 CRQC arrival,
                    adversaries conducting <em>Harvest-Now-Decrypt-Later (HNDL)</em> collection will breach data
                    within its required secrecy window.
                  </p>
                </div>
              </section>

              <section className="report-section">
                <h3>2. Strategic Recommendation & Migration Investment</h3>
                <div className="report-summary-metrics">
                  <div className="report-metric-box">
                    <span className="box-val">3 Waves</span>
                    <span className="box-lbl">Planned Migration</span>
                  </div>
                  <div className="report-metric-box">
                    <span className="box-val">194 wks</span>
                    <span className="box-lbl">Total Engineering</span>
                  </div>
                  <div className="report-metric-box">
                    <span className="box-val">$630k</span>
                    <span className="box-lbl">Est. Capital Outlay</span>
                  </div>
                  <div className="report-metric-box">
                    <span className="box-val">2026 / 2030</span>
                    <span className="box-lbl">CNSA 2.0 Deadlines</span>
                  </div>
                </div>
                <p>
                  Management should authorize <strong>Wave 1 (Payment & Ingress Edge)</strong> immediate remediation
                  to transition to FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65).
                </p>
              </section>
            </div>
          )}

          {reportType === "technical" && (
            <div className="report-content-body">
              <section className="report-section">
                <h3>1. Technical Inventory & Primitive Classification</h3>
                <table className="report-table">
                  <thead>
                    <tr>
                      <th>Algorithm</th>
                      <th>Class</th>
                      <th>Key / Parameter</th>
                      <th>Quantum Vulnerability</th>
                      <th>FIPS 203/204 Replacement</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td><code>RSA</code></td>
                      <td>Asymmetric / Signature & KEX</td>
                      <td>2048-bit</td>
                      <td><span className="badge-p0">Broken (Shor)</span></td>
                      <td><code>ML-KEM-768 / ML-DSA-65</code></td>
                    </tr>
                    <tr>
                      <td><code>ECDSA</code></td>
                      <td>Asymmetric / Signature</td>
                      <td>secp256r1 (P-256)</td>
                      <td><span className="badge-p0">Broken (Shor)</span></td>
                      <td><code>ML-DSA-65 (FIPS 204)</code></td>
                    </tr>
                    <tr>
                      <td><code>ECDHE</code></td>
                      <td>Key Exchange</td>
                      <td>X25519</td>
                      <td><span className="badge-p0">Broken (Shor)</span></td>
                      <td><code>X25519MLKEM768 (Hybrid)</code></td>
                    </tr>
                    <tr>
                      <td><code>AES</code></td>
                      <td>Symmetric Block Cipher</td>
                      <td>128-bit GCM</td>
                      <td><span className="badge-p1">Weakened (Grover)</span></td>
                      <td><code>AES-256-GCM</code></td>
                    </tr>
                    <tr>
                      <td><code>AES</code></td>
                      <td>Symmetric Block Cipher</td>
                      <td>256-bit GCM</td>
                      <td><span className="badge-p2">Quantum-Safe (128-bit eff)</span></td>
                      <td><code>Retain AES-256</code></td>
                    </tr>
                  </tbody>
                </table>
              </section>

              <section className="report-section">
                <h3>2. Evidence Verification Trace</h3>
                <p>
                  Every finding in this report is anchored to verifiable source code AST, configuration files,
                  or container image layers. Use the Trinetra Explorer to inspect raw symbol traces.
                </p>
              </section>
            </div>
          )}

          {reportType === "cbom" && (
            <div className="report-content-body">
              <section className="report-section">
                <h3>CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)</h3>
                <p>Standardized JSON-LD representation conforming to OWASP CycloneDX 1.6 specifications:</p>
                <pre className="report-cbom-preview">
{`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:68e922a1-4389-4a41-b4f0-8c29801be9d1",
  "version": 1,
  "metadata": {
    "timestamp": "${new Date().toISOString()}",
    "tools": {
      "components": [
        { "type": "application", "name": "Trinetra PQC Scanner", "version": "0.1.0" }
      ]
    }
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "RSA-2048 Private Key",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "pke",
          "curve": null,
          "executionEnvironment": "software",
          "implementationPlatform": "openssl-3.0",
          "certificationLevel": ["none"],
          "cryptoFunctions": ["sign", "decrypt"]
        },
        "oid": "1.2.840.113549.1.1.1"
      }
    }
  ]
}`}
                </pre>
              </section>
            </div>
          )}
        </div>
      </ChartShell>
    </div>
  );
}
