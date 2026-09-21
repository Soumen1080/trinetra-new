import { useRef } from "react";
import { Link } from "react-router-dom";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { Artefact } from "../api/client";
import { riskBand, riskCopy, titleCase } from "../risk";
import { RiskBadge } from "./RiskBadge";

/** Asset-type icons (§4.8c — consistent iconography per type). */
const TYPE_ICONS: Record<string, string> = {
  algorithm: "🔐",
  key: "🗝",
  certificate: "📜",
  protocol: "🔗",
  library: "📦",
  hardware_module: "💾",
  cloud_service: "☁",
  related_material: "📎",
};

function typeIcon(type?: string | null) {
  return TYPE_ICONS[type?.toLowerCase() ?? ""] ?? "⬡";
}

interface ArtefactTableProps {
  rows: Artefact[];
  compact?: boolean;
  /** When true the table uses TanStack Virtual for 100k-row smoothness (§4.10a). */
  virtualized?: boolean;
  /** If provided, clicking a row navigates here instead of the default artefact page. */
  linkFor?: (artefact: Artefact) => string;
  selectable?: boolean;
  selected?: string[];
  onToggle?: (id: string) => void;
  showEvidence?: boolean;
  showSource?: boolean;
}

/**
 * Virtualised artefact table.
 * - Default sort is risk-descending (§4.2e — the worst row is always first).
 * - Column set is sensible by default; extra columns opt-in (§4.2d).
 * - Stays smooth at 100k rows via TanStack Virtual (§4.10a).
 */
export function ArtefactTable({
  rows,
  compact = false,
  virtualized = false,
  linkFor,
  selectable = false,
  selected = [],
  onToggle,
  showEvidence = true,
  showSource = true,
}: ArtefactTableProps) {
  const parent = useRef<HTMLDivElement>(null);
  const rowHeight = 72;
  const virtualizer = useVirtualizer({
    count: virtualized ? rows.length : 0,
    getScrollElement: () => parent.current,
    estimateSize: () => rowHeight,
    overscan: 10,
  });

  const visible = virtualized
    ? virtualizer.getVirtualItems()
    : rows.map((_, index) => ({ index, start: index * rowHeight, size: rowHeight, key: index }));

  const columns = [
    selectable ? "40px" : "",
    "minmax(220px, 2fr)",
    showEvidence ? "minmax(240px, 2.2fr)" : "",
    !compact && showSource ? "minmax(110px, 0.9fr)" : "",
    "minmax(140px, 1.1fr)",
    "minmax(160px, 1.4fr)",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div className={`artefact-table${virtualized ? " virtual" : ""}`} ref={parent}>
      <div className="table-head" style={{ gridTemplateColumns: columns }}>
        {selectable && <span className="col-select">Select</span>}
        <span className="col-artefact">Artefact</span>
        {showEvidence && <span className="col-evidence">Evidence</span>}
        {!compact && showSource && <span className="col-source">Source</span>}
        <span className="col-risk">Risk</span>
        <span className="col-action">Next step</span>
      </div>
      <div
        className="table-body"
        style={
          virtualized
            ? { height: `${virtualizer.getTotalSize()}px`, position: "relative", width: "100%", minWidth: "750px" }
            : { width: "100%", minWidth: "750px" }
        }
      >
        {visible.map((item) => {
          const row = rows[item.index];
          if (!row) return null;
          const band = riskBand(row.priority);
          return (
            <Link
              className={`table-row table-row-${band}`}
              style={{
                gridTemplateColumns: columns,
                ...(virtualized
                  ? {
                      position: "absolute",
                      top: 0,
                      left: 0,
                      transform: `translateY(${item.start}px)`,
                      height: `${item.size}px`,
                      width: "100%",
                    }
                  : {}),
              }}
              to={linkFor?.(row) ?? `/artefacts/${row.id}`}
              key={row.id}
            >
              {selectable && (
                <span
                  onClick={(event) => event.preventDefault()}
                  className="row-select"
                >
                  <input
                    type="checkbox"
                    aria-label={`Select ${row.name}`}
                    checked={selected.includes(row.id)}
                    onChange={() => onToggle?.(row.id)}
                  />
                </span>
              )}
              <span className="row-name">
                <span className="row-type-icon" aria-hidden="true">
                  {typeIcon(row.type)}
                </span>
                <span className="row-name-details">
                  <b className="row-title" title={row.name}>{row.name}</b>
                  <small className="row-meta">
                    <span className="row-meta-type">{titleCase(row.type)}</span>
                    <span className="row-meta-sep">·</span>
                    <span className="row-meta-algo">{row.algorithm || "Algorithm unknown"}</span>
                  </small>
                </span>
              </span>
              {showEvidence && (
                <span className="row-evidence">
                  <small className="evidence-location" title={row.location || "Location unavailable"}>
                    {row.location || "Location unavailable"}
                  </small>
                </span>
              )}
              {!compact && showSource && (
                <span className="row-source">
                  <span className="source-pill">
                    <span className="source-dot" aria-hidden="true" />
                    {titleCase(row.discovered_by || "Scanner")}
                  </span>
                </span>
              )}
              <span className="row-risk">
                <div className="risk-cell-box">
                  <RiskBadge priority={row.priority} />
                  <small className="risk-score-val">
                    {row.risk_score == null
                      ? "Score pending"
                      : `${row.risk_score.toFixed(1)} / 100`}
                  </small>
                </div>
              </span>
              <span className="row-action">
                <small className="row-action-text" title={row.review_status ? `${titleCase(row.review_status)}${row.review_owner ? ` · ${row.review_owner}` : ""}` : row.recommendation || riskCopy[band].action}>
                  {row.review_status
                    ? `${titleCase(row.review_status)}${row.review_owner ? ` · ${row.review_owner}` : ""}`
                    : row.recommendation || riskCopy[band].action}
                </small>
              </span>
            </Link>
          );
        })}
      </div>
    </div>
  );
}

/** Pagination footer (used by ExplorerPage). */
export function Pagination({
  page,
  setPage,
}: {
  page: { offset: number; limit: number; total: number };
  setPage: (offset: number) => void;
}) {
  const from = page.total ? page.offset + 1 : 0;
  const to = Math.min(page.offset + page.limit, page.total);
  return (
    <footer className="pagination">
      <span>
        Showing {from}–{to} of {page.total.toLocaleString()}
      </span>
      <button disabled={page.offset === 0} onClick={() => setPage(Math.max(0, page.offset - page.limit))}>
        ← Previous
      </button>
      <button
        disabled={page.offset + page.limit >= page.total}
        onClick={() => setPage(page.offset + page.limit)}
      >
        Next →
      </button>
    </footer>
  );
}
