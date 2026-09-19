import { useState, useMemo } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip,
  Legend, ResponsiveContainer,
} from "recharts";
import { ChartShell } from "./ChartShell";
import type { ComplianceData } from "../api/client";

export interface Milestone {
  year: number;
  label: string;
  authority: string;
  scope: string;
  compliantCount: number;
  atRiskCount: number;
  nonCompliantCount: number;
}

export interface SystemComplianceRecord {
  id: string;
  systemName: string;
  standard: "CNSA 2.0" | "NIST IR 8547" | "FIPS 203/204" | "BSI TR-02102";
  currentCrypto: string;
  targetDeadline: number;
  status: "on_track" | "at_risk" | "non_compliant";
  gapAnalysis: string;
}

const DEFAULT_MILESTONES: Milestone[] = [
  {
    year: 2026,
    label: "Software & Firmware Signatures",
    authority: "CNSA 2.0 Phase 1",
    scope: "Code signing, OS boot loaders, PKI root certificates for new deployments",
    compliantCount: 3,
    atRiskCount: 2,
    nonCompliantCount: 1,
  },
  {
    year: 2030,
    label: "Web Browsers, TLS & Cloud",
    authority: "CNSA 2.0 Phase 2 / NIST IR 8547",
    scope: "Public HTTPS, TLS 1.3 key exchange, API gateways, Cloud workloads",
    compliantCount: 8,
    atRiskCount: 11,
    nonCompliantCount: 5,
  },
  {
    year: 2033,
    label: "Operating Systems & Networking",
    authority: "CNSA 2.0 Phase 3",
    scope: "Core switches, routers, VPN concentrators, storage encryption at rest",
    compliantCount: 12,
    atRiskCount: 9,
    nonCompliantCount: 7,
  },
  {
    year: 2035,
    label: "Full Legacy & Deep Embedded",
    authority: "CNSA 2.0 Absolute Cutoff",
    scope: "All remaining legacy hardware, IoT devices, historical data vaults",
    compliantCount: 18,
    atRiskCount: 4,
    nonCompliantCount: 2,
  },
];

const DEFAULT_SYSTEM_RECORDS: SystemComplianceRecord[] = [
  {
    id: "comp-1",
    systemName: "Payment Gateway Core",
    standard: "CNSA 2.0",
    currentCrypto: "ECDHE-P256 / RSA-2048",
    targetDeadline: 2030,
    status: "at_risk",
    gapAnalysis: "Must replace ECDHE with ML-KEM-768/1024 before 2030 TLS cutover.",
  },
  {
    id: "comp-2",
    systemName: "Public Web & Ingress Edge",
    standard: "NIST IR 8547",
    currentCrypto: "RSA-2048 Cert / ECDHE",
    targetDeadline: 2026,
    status: "non_compliant",
    gapAnalysis: "Dual-cert or hybrid ML-DSA root certificate required by 2026 for government ingress.",
  },
  {
    id: "comp-3",
    systemName: "Customer Auth (Keycloak)",
    standard: "FIPS 203/204",
    currentCrypto: "RSA-3072 / ES256",
    targetDeadline: 2030,
    status: "at_risk",
    gapAnalysis: "JWT token signing library does not yet support ML-DSA-44 or ML-DSA-65.",
  },
  {
    id: "comp-4",
    systemName: "Internal Storage Vault",
    standard: "CNSA 2.0",
    currentCrypto: "AES-256-GCM",
    targetDeadline: 2033,
    status: "on_track",
    gapAnalysis: "Symmetric key length already compliant (AES-256 is quantum-safe per Grover).",
  },
  {
    id: "comp-5",
    systemName: "Firmware Build Pipeline",
    standard: "CNSA 2.0",
    currentCrypto: "RSA-4096 PSS",
    targetDeadline: 2026,
    status: "at_risk",
    gapAnalysis: "Requires transition to ML-DSA-87 or SLH-DSA-256 for secure boot verification.",
  },
  {
    id: "comp-6",
    systemName: "Corporate VPN Concentrator",
    standard: "BSI TR-02102",
    currentCrypto: "IKEv2 DH Group 14 (2048-bit)",
    targetDeadline: 2030,
    status: "non_compliant",
    gapAnalysis: "Classic DH group 14 forbidden. Requires FrodoKEM or ML-KEM hybrid IKEv2.",
  },
];

interface ComplianceDashboardProps {
  data?: ComplianceData;
  loading?: boolean;
}

export function ComplianceDashboard({
  data,
  loading = false,
}: ComplianceDashboardProps) {
  const [selectedStandard, setSelectedStandard] = useState<string>("all");
  const [selectedStatus, setSelectedStatus] = useState<string>("all");

  const milestones = DEFAULT_MILESTONES;
  const records = DEFAULT_SYSTEM_RECORDS;

  const chartData = useMemo(() => {
    return milestones.map((m) => ({
      name: `${m.year} (${m.label.split(" ")[0]})`,
      year: m.year,
      label: m.label,
      "On Track / Compliant": m.compliantCount,
      "At Risk": m.atRiskCount,
      "Non-Compliant": m.nonCompliantCount,
    }));
  }, [milestones]);

  const filteredRecords = useMemo(() => {
    return records.filter((r) => {
      const matchStd = selectedStandard === "all" || r.standard === selectedStandard;
      const matchStatus = selectedStatus === "all" || r.status === selectedStatus;
      return matchStd && matchStatus;
    });
  }, [records, selectedStandard, selectedStatus]);

  const dataTable = (
    <table className="data-table">
      <thead>
        <tr>
          <th>System</th>
          <th>Standard</th>
          <th>Current Cryptography</th>
          <th>Mandate Deadline</th>
          <th>Status</th>
          <th>Gap Analysis & Remediation</th>
        </tr>
      </thead>
      <tbody>
        {filteredRecords.map((r) => (
          <tr key={r.id}>
            <td><strong>{r.systemName}</strong></td>
            <td><code>{r.standard}</code></td>
            <td>{r.currentCrypto}</td>
            <td>{r.targetDeadline}</td>
            <td>
              {r.status === "on_track" && <span className="badge-p2">✅ On Track</span>}
              {r.status === "at_risk" && <span className="badge-p1">⚠ At Risk</span>}
              {r.status === "non_compliant" && <span className="badge-p0">❌ Non-Compliant</span>}
            </td>
            <td>{r.gapAnalysis}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );

  return (
    <div className="compliance-dashboard">
      {/* Milestone Cards Bar */}
      <div className="compliance-milestones-grid">
        {milestones.map((m) => {
          const currentYear = new Date().getFullYear();
          const yearsLeft = m.year - currentYear;
          return (
            <div key={m.year} className="milestone-card">
              <div className="milestone-year-row">
                <span className="milestone-year">{m.year}</span>
                <span className="milestone-countdown">
                  {yearsLeft > 0 ? `${yearsLeft} yrs remaining` : "Current Year"}
                </span>
              </div>
              <h4 className="milestone-label">{m.label}</h4>
              <span className="milestone-auth">{m.authority}</span>
              <p className="milestone-scope">{m.scope}</p>
              <div className="milestone-stats">
                <span className="stat-item on-track">✅ {m.compliantCount} Ready</span>
                <span className="stat-item at-risk">⚠ {m.atRiskCount} At Risk</span>
                <span className="stat-item non-compliant">❌ {m.nonCompliantCount} Non-Compliant</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Compliance Timeline BarChart Shell */}
      <ChartShell
        title="CNSA 2.0 & NIST IR 8547 Regulatory Timeline"
        explainer={
          <div>
            <p><strong>How to read this Compliance Dashboard:</strong></p>
            <p>
              Governmental and industry bodies have published binding deadlines to phase out classical
              public-key algorithms (RSA, ECC, DH) and transition to post-quantum standards:
            </p>
            <ul>
              <li>
                <strong>CNSA 2.0 (Commercial National Security Algorithm Suite 2.0):</strong> Mandates
                FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) for all national security systems and contractors.
              </li>
              <li>
                <strong>NIST IR 8547:</strong> Guidance on transitions to post-quantum cryptographic standards
                across federal agencies and critical infrastructure.
              </li>
              <li>
                <strong>Status definitions:</strong>
                <ul>
                  <li><strong style={{ color: "var(--p2)" }}>On Track:</strong> PQC algorithms integrated or tested in staging.</li>
                  <li><strong style={{ color: "var(--p1)" }}>At Risk:</strong> In scope for approaching deadline without an assigned migration ticket.</li>
                  <li><strong style={{ color: "var(--p0)" }}>Non-Compliant:</strong> Classic crypto in production past or within 12 months of mandate without migration plan.</li>
                </ul>
              </li>
            </ul>
          </div>
        }
        note="System readiness across upcoming regulatory enforcement horizons."
        dataTable={dataTable}
        loading={loading}
        height={320}
        action={
          <div className="compliance-filters" style={{ display: "flex", gap: "0.5rem" }}>
            <select
              value={selectedStandard}
              onChange={(e) => setSelectedStandard(e.target.value)}
              className="select-input"
              aria-label="Filter by standard"
            >
              <option value="all">All Standards</option>
              <option value="CNSA 2.0">CNSA 2.0</option>
              <option value="NIST IR 8547">NIST IR 8547</option>
              <option value="FIPS 203/204">FIPS 203/204</option>
              <option value="BSI TR-02102">BSI TR-02102</option>
            </select>
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="select-input"
              aria-label="Filter by status"
            >
              <option value="all">All Statuses</option>
              <option value="on_track">On Track Only</option>
              <option value="at_risk">At Risk Only</option>
              <option value="non_compliant">Non-Compliant Only</option>
            </select>
          </div>
        }
      >
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" />
            <XAxis dataKey="name" stroke="var(--muted)" tick={{ fill: "var(--text-2)", fontSize: 11 }} />
            <YAxis stroke="var(--muted)" tick={{ fill: "var(--muted)", fontSize: 11 }} />
            <RechartsTooltip
              contentStyle={{
                background: "var(--surface)",
                borderColor: "var(--line)",
                borderRadius: "6px",
              }}
            />
            <Legend wrapperStyle={{ paddingTop: "10px", fontSize: "12px" }} />
            <Bar dataKey="On Track / Compliant" stackId="a" fill="var(--p2)" radius={[0, 0, 0, 0]} />
            <Bar dataKey="At Risk" stackId="a" fill="var(--p1)" radius={[0, 0, 0, 0]} />
            <Bar dataKey="Non-Compliant" stackId="a" fill="var(--p0)" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </ChartShell>

      {/* System Compliance Table */}
      <div className="compliance-table-panel">
        <div className="table-header-row">
          <h3>Systems Compliance Ledger ({filteredRecords.length} systems)</h3>
          <span className="table-sub">Mapped against CNSA 2.0 & NIST IR 8547 mandates</span>
        </div>
        {dataTable}
      </div>
    </div>
  );
}
