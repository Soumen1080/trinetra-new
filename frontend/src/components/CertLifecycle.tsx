import { Link } from "react-router-dom";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  Cell, ResponsiveContainer,
} from "recharts";
import type { Artefact } from "../api/client";
import { ChartShell } from "./ChartShell";
import { formatDate } from "../risk";

const MONTH_NAMES = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];

interface CertLifecycleProps {
  certificates: Artefact[];
  loading?: boolean;
}

type CertEntry = Artefact & {
  expiry?: string | null;
  issuer?: string | null;
  subject?: string | null;
  sig_algorithm?: string | null;
};

/** Quantum-vulnerable signature algorithms */
const VULNERABLE_ALGOS = new Set(["RSA", "ECDSA", "DSA", "SHA1withRSA", "SHA256withRSA"]);

/**
 * 10.5 — Certificate lifecycle view.
 * Three sections:
 * 1. Expiry calendar: monthly bar chart of certificates expiring each month
 * 2. Signature-algorithm distribution: bar chart, vulnerable ones in red
 * 3. Chains with quantum-vulnerable roots: list
 */
export function CertLifecycle({ certificates, loading = false }: CertLifecycleProps) {
  const certs = certificates as CertEntry[];

  // ── Expiry calendar
  const now = new Date();
  const expiryCounts: Record<string, number> = {};
  const expiryLabels: Array<{ label: string; count: number; year: number; month: number }> = [];

  for (let i = 0; i < 18; i++) {
    const d = new Date(now.getFullYear(), now.getMonth() + i, 1);
    expiryCounts[`${d.getFullYear()}-${d.getMonth()}`] = 0;
  }
  for (const cert of certs) {
    if (!cert.expiry) continue;
    const d = new Date(cert.expiry);
    const key = `${d.getFullYear()}-${d.getMonth()}`;
    if (key in expiryCounts) expiryCounts[key]++;
  }
  for (let i = 0; i < 18; i++) {
    const d = new Date(now.getFullYear(), now.getMonth() + i, 1);
    const key = `${d.getFullYear()}-${d.getMonth()}`;
    expiryLabels.push({
      label: `${MONTH_NAMES[d.getMonth()]} ${d.getFullYear().toString().slice(2)}`,
      count: expiryCounts[key] ?? 0,
      year: d.getFullYear(),
      month: d.getMonth(),
    });
  }

  // ── Algorithm distribution
  const algoCounts: Record<string, number> = {};
  for (const cert of certs) {
    const algo = cert.sig_algorithm ?? cert.algorithm ?? "Unknown";
    algoCounts[algo] = (algoCounts[algo] ?? 0) + 1;
  }
  const algoData = Object.entries(algoCounts)
    .map(([name, count]) => ({ name, count, vulnerable: VULNERABLE_ALGOS.has(name.split("-")[0]) }))
    .sort((a, b) => b.count - a.count);

  // ── Vulnerable chains
  const vulnerableChains = certs.filter(
    (c) => VULNERABLE_ALGOS.has((c.sig_algorithm ?? c.algorithm ?? "").split("-")[0]),
  );

  const dataTable = (
    <table>
      <thead><tr><th>Certificate</th><th>Algorithm</th><th>Expires</th><th>Location</th></tr></thead>
      <tbody>
        {certs.map((c) => (
          <tr key={c.id}>
            <td><Link to={`/artefacts/${c.id}`}>{c.name}</Link></td>
            <td>{c.sig_algorithm ?? c.algorithm ?? "Unknown"}</td>
            <td>{c.expiry ? formatDate(c.expiry) : "No expiry"}</td>
            <td>{c.location ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );

  return (
    <ChartShell
      title="Certificate Lifecycle"
      explainer={
        <div>
          <p><strong>How to read this view:</strong></p>
          <p>The <strong>expiry calendar</strong> shows how many certificates expire each month. Certificates signed with vulnerable algorithms (RSA, ECDSA) need replacement with quantum-safe alternatives <em>when they are next renewed</em> — not necessarily all at once.</p>
          <p>The <strong>algorithm chart</strong> shows distribution of signing algorithms. Red bars = quantum-vulnerable.</p>
          <p>The <strong>vulnerable chains</strong> list shows certificates whose signature algorithm can be broken by Shor's algorithm on a CRQC.</p>
        </div>
      }
      note="Renewal cycles are the natural migration window. Red = quantum-vulnerable algorithm."
      dataTable={dataTable}
      loading={loading}
      height="auto"
    >
      <div className="cert-layout">
        <section className="cert-section">
          <h3>Expiry calendar — next 18 months</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={expiryLabels} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="var(--line)" />
              <XAxis dataKey="label" tick={{ fill: "var(--muted)", fontSize: 10 }} />
              <YAxis tick={{ fill: "var(--muted)", fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--line)", borderRadius: "6px" }} />
              <Bar dataKey="count" name="Certs expiring">
                {expiryLabels.map((entry, index) => (
                  <Cell
                    key={index}
                    fill={entry.count > 5 ? "var(--p0)" : entry.count > 2 ? "var(--p1)" : "var(--brand)"}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </section>

        <section className="cert-section">
          <h3>Signature algorithm distribution</h3>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={algoData} layout="vertical" margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
              <CartesianGrid horizontal={false} strokeDasharray="3 3" stroke="var(--line)" />
              <XAxis type="number" tick={{ fill: "var(--muted)", fontSize: 11 }} />
              <YAxis type="category" dataKey="name" width={120} tick={{ fill: "var(--text-2)", fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--line)", borderRadius: "6px" }} />
              <Bar dataKey="count" name="Count">
                {algoData.map((entry, index) => (
                  <Cell key={index} fill={entry.vulnerable ? "var(--p0)" : "var(--p2)"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </section>

        <section className="cert-section">
          <h3>
            Quantum-vulnerable roots ({vulnerableChains.length})
          </h3>
          {vulnerableChains.length === 0 ? (
            <p className="muted">No certificates using vulnerable signature algorithms found.</p>
          ) : (
            <ul className="cert-chain-list">
              {vulnerableChains.slice(0, 12).map((c) => (
                <li key={c.id}>
                  <Link to={`/artefacts/${c.id}`}>{c.name}</Link>
                  <small>
                    {c.sig_algorithm ?? c.algorithm} ·{" "}
                    {c.expiry ? `Expires ${formatDate(c.expiry)}` : "No expiry set"}
                  </small>
                </li>
              ))}
              {vulnerableChains.length > 12 && (
                <li className="muted">+ {vulnerableChains.length - 12} more · <Link to="/explorer?type=certificate">View all</Link></li>
              )}
            </ul>
          )}
        </section>
      </div>
    </ChartShell>
  );
}
