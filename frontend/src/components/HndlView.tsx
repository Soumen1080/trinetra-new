import { Link } from "react-router-dom";
import type { Artefact } from "../api/client";
import { RiskBadge } from "./RiskBadge";
import { ChartShell } from "./ChartShell";
import { titleCase } from "../risk";

interface HndlViewProps {
  items: Artefact[];
  loading?: boolean;
}

/**
 * 10.4 — HNDL (Harvest Now, Decrypt Later) exposure view.
 * Lists externally-exposed, long-lived-data, classical-KEX artefacts
 * sorted by Mosca urgency. Each card gives a plain-English explanation
 * of why this system is at risk — satisfying §4.3b on the most urgent screen.
 */
export function HndlView({ items, loading = false }: HndlViewProps) {
  const dataTable = (
    <table>
      <thead>
        <tr><th>System</th><th>Algorithm</th><th>Risk</th><th>Location</th></tr>
      </thead>
      <tbody>
        {items.map((item) => (
          <tr key={item.id}>
            <td><Link to={`/artefacts/${item.id}`}>{item.name}</Link></td>
            <td>{item.algorithm ?? "Unknown"}</td>
            <td>{item.priority ?? "—"}</td>
            <td>{item.location ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );

  return (
    <ChartShell
      title="HNDL Exposure"
      explainer={
        <div>
          <p><strong>How to read this view:</strong></p>
          <p><strong>HNDL</strong> (Harvest Now, Decrypt Later) is an attack where an adversary records encrypted traffic today and decrypts it when a quantum computer arrives.</p>
          <p>This list shows systems at highest HNDL risk: they protect <strong>long-lived sensitive data</strong> using classical key exchange (RSA, ECDH, DH) that will be broken by Shor's algorithm on a CRQC.</p>
          <p>Sort order = urgency: systems whose Mosca deadline arrives soonest are first. The "act this quarter" label means migration should have started already.</p>
        </div>
      }
      note="Sorted by Mosca urgency. These systems protect long-lived data with classical KEX."
      dataTable={dataTable}
      loading={loading}
      height="auto"
    >
      {items.length === 0 ? (
        <div className="empty">
          <div className="empty-mark">🔒</div>
          <h2>No HNDL-exposed artefacts found</h2>
          <p>Either no artefacts match the HNDL criteria in this project, or the risk endpoint has not returned HNDL data yet. Complete Mosca context and rescan.</p>
        </div>
      ) : (
        <ul className="hndl-list">
          {items.map((item) => (
            <li key={item.id} className={`hndl-card hndl-${item.priority ?? "none"}`}>
              <div className="hndl-card-header">
                <RiskBadge priority={item.priority} />
                <Link to={`/artefacts/${item.id}`} className="hndl-name">{item.name}</Link>
              </div>
              <p className="hndl-summary">
                {buildHndlSummary(item)}
              </p>
              <dl className="hndl-meta">
                <dt>Algorithm</dt>
                <dd>{item.algorithm ?? "Unknown"}</dd>
                <dt>Type</dt>
                <dd>{titleCase(item.type)}</dd>
                {item.location && <><dt>Location</dt><dd className="mono">{item.location}</dd></>}
              </dl>
            </li>
          ))}
        </ul>
      )}
    </ChartShell>
  );
}

function buildHndlSummary(item: Artefact): string {
  const algo = item.algorithm ?? "this algorithm";
  return (
    item.recommendation ||
    `${algo} is vulnerable to Shor's algorithm and is being used to protect data. An adversary recording this traffic today could decrypt it when a cryptographically-relevant quantum computer arrives. This is an immediate migration priority.`
  );
}
