import { useNavigate } from "react-router-dom";
import type { HeatmapData } from "../api/client";
import { ChartShell } from "./ChartShell";

const CRITICALITY_LABELS = ["Unknown", "Low", "Medium", "High", "Critical"];
const VULN_LABELS = ["Not assessed", "Low", "Medium", "High", "Critical"];

/** Colour matrix: criticality (row) × vulnerability (col) — green→amber→red */
function cellColour(criticality: number, vuln: number): string {
  const score = (criticality + vuln) / 2;
  if (score < 1) return "var(--none-bg)";
  if (score < 2) return "#2a4a2e";   // dark green
  if (score < 3) return "var(--p1-bg)";
  if (score < 4) return "#4a2e0a";   // deep amber
  return "var(--p0-bg)";
}
function textColour(criticality: number, vuln: number): string {
  const score = (criticality + vuln) / 2;
  if (score < 1) return "var(--none)";
  if (score < 2) return "#4ecdc4";
  if (score < 3) return "var(--p1)";
  if (score < 4) return "#ffb347";
  return "var(--p0)";
}

interface RiskHeatmapProps {
  data: HeatmapData;
  loading?: boolean;
}

/**
 * 10.2 — Risk heatmap: business criticality × quantum vulnerability.
 * 5×5 grid; clicking a cell navigates to Explorer with matching filters.
 * Colour encodes risk with text counts for accessibility (§4.9b).
 */
export function RiskHeatmap({ data, loading = false }: RiskHeatmapProps) {
  const navigate = useNavigate();

  // Build a lookup: (criticality_bin, vuln_bin) → count
  const lookup: Record<string, number> = {};
  const appLookup: Record<string, string[]> = {};
  for (const cell of data.cells) {
    const key = `${cell.criticality_bin}-${cell.vuln_bin}`;
    lookup[key] = (lookup[key] ?? 0) + cell.count;
    appLookup[key] = [...(appLookup[key] ?? []), ...cell.application_ids];
  }

  const handleClick = (crit: number, vuln: number) => {
    const vulnParam = vuln >= 3 ? "vulnerable" : vuln >= 2 ? "partially_vulnerable" : "safe";
    navigate(`/explorer?quantum_status=${vulnParam}&priority=${crit >= 3 ? "p0" : crit >= 2 ? "p1" : ""}`);
  };

  const maxCount = Math.max(1, ...data.cells.map((c) => c.count));

  const dataTable = (
    <table>
      <thead>
        <tr>
          <th>Criticality \ Vulnerability</th>
          {VULN_LABELS.map((v) => <th key={v}>{v}</th>)}
        </tr>
      </thead>
      <tbody>
        {CRITICALITY_LABELS.map((cLabel, cIndex) => (
          <tr key={cLabel}>
            <td><strong>{cLabel}</strong></td>
            {VULN_LABELS.map((_, vIndex) => (
              <td key={vIndex}>{lookup[`${cIndex}-${vIndex}`] ?? 0}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );

  return (
    <ChartShell
      title="Risk Heatmap"
      explainer={
        <div>
          <p><strong>How to read this chart:</strong></p>
          <p>Each cell shows how many systems fall at a given intersection of <strong>business criticality</strong> (rows, top = most critical) and <strong>quantum vulnerability</strong> (columns, right = most vulnerable).</p>
          <p>The <span style={{ color: "var(--p0)" }}>top-right cells</span> are the highest priority — critical business systems with high quantum exposure. Click any cell to open the Explorer filtered to those systems.</p>
          <p>Colour alone is never the only signal — each cell also shows a count number.</p>
        </div>
      }
      note="Click a cell to open filtered Explorer results. Colour + count encode risk level."
      dataTable={dataTable}
      loading={loading}
      height={320}
    >
      <div className="heatmap-grid" aria-label="Risk heatmap: criticality by quantum vulnerability">
        {/* Column headers */}
        <div className="heatmap-corner" />
        {VULN_LABELS.map((label) => (
          <div key={label} className="heatmap-col-header">{label}</div>
        ))}
        {/* Rows — rendered bottom-to-top (highest criticality at top) */}
        {[...CRITICALITY_LABELS].reverse().map((cLabel, rIndex) => {
          const cIndex = CRITICALITY_LABELS.length - 1 - rIndex;
          return [
            <div key={`row-${cLabel}`} className="heatmap-row-header">{cLabel}</div>,
            ...VULN_LABELS.map((_, vIndex) => {
              const count = lookup[`${cIndex}-${vIndex}`] ?? 0;
              const pct = count / maxCount;
              return (
                <button
                  key={`${cIndex}-${vIndex}`}
                  className="heatmap-cell"
                  style={{
                    background: cellColour(cIndex, vIndex),
                    opacity: count === 0 ? 0.3 : 0.5 + pct * 0.5,
                    color: textColour(cIndex, vIndex),
                  }}
                  onClick={() => handleClick(cIndex, vIndex)}
                  aria-label={`${cLabel} criticality, ${VULN_LABELS[vIndex]} vulnerability: ${count} systems`}
                  disabled={count === 0}
                >
                  {count > 0 && <b>{count}</b>}
                </button>
              );
            }),
          ];
        })}
      </div>
    </ChartShell>
  );
}
