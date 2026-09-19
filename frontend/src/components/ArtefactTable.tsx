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
  const virtualizer = useVirtualizer({
    count: virtualized ? rows.length : 0,
    getScrollElement: () => parent.current,
    estimateSize: () => 62,
    overscan: 8,
  });

  const visible = virtualized
    ? virtualizer.getVirtualItems()
    : rows.map((_, index) => ({ index, start: index * 62, size: 62, key: index }));

  const columns = [
    selectable ? "32px" : "",
    "1.6fr",
    showEvidence ? "1.3fr" : "",
    !compact && showSource ? ".8fr" : "",
    ".95fr",
    "1fr",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div className={`artefact-table${virtualized ? " virtual" : ""}`} ref={parent}>
      <div className="table-head" style={{ gridTemplateColumns: columns }}>
        {selectable && <span>Select</span>}
        <span>Artefact</span>
        {showEvidence && <span>Evidence</span>}
        {!compact && showSource && <span>Source</span>}
        <span>Risk</span>
        <span>Next step</span>
      </div>
      <div
        style={
          virtualized
            ? { height: `${virtualizer.getTotalSize()}px`, position: "relative" }
            : undefined
        }
      >
        {visible.map((item) => {
          const row = rows[item.index];
          const band = riskBand(row.priority);
          return (
            <Link
              className={`table-row table-row-${band}`}
              style={
                virtualized
                  ? {
                      position: "absolute",
                      transform: `translateY(${item.start}px)`,
                      height: item.size,
                      width: "100%",
                    }
                  : {}
              }
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
                <span>
                  <b>{row.name}</b>
                  <small>
                    {titleCase(row.type)} · {row.algorithm || "Algorithm unknown"}
                  </small>
                </span>
              </span>
              {showEvidence && (
                <span>
                  <small className="evidence-location">{row.location || "Location unavailable"}</small>
                </span>
              )}
              {!compact && showSource && (
                <span>
                  <small>{titleCase(row.discovered_by)}</small>
                </span>
              )}
              <span>
                <RiskBadge priority={row.priority} />
                <small>
                  {row.risk_score == null
                    ? "No score — context needed"
                    : `${row.risk_score.toFixed(1)} / 100`}
                </small>
              </span>
              <span>
                <small>
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
