import { useState } from "react";
import type { ReactNode } from "react";
import { Skeleton } from "./Skeleton";

interface ChartShellProps {
  /** Chart heading */
  title: string;
  /** §4.11c — how to read this chart. Required for every visualisation. */
  explainer: ReactNode;
  /** Optional subtitle / scope note */
  note?: ReactNode;
  /** The chart itself (SVG, Cytoscape div, etc.) */
  children: ReactNode;
  /** §4.9e — accessible data table rendered as alternative */
  dataTable?: ReactNode;
  /** Optional action placed in the header (e.g. a filter control) */
  action?: ReactNode;
  /** While true renders skeleton instead of children */
  loading?: boolean;
  /** Height of the chart region */
  height?: number | string;
}

/**
 * Universal chart wrapper satisfying:
 * - §4.11c / 10.12 — "?" explainer popover on every visualisation
 * - §4.9e / 10.13 — "Show data table" toggle for accessible alternative
 * - Breadcrumbs and URL-addressing are handled by the parent page
 */
export function ChartShell({
  title,
  explainer,
  note,
  children,
  dataTable,
  action,
  loading = false,
  height = 340,
}: ChartShellProps) {
  const [tableOpen, setTableOpen] = useState(false);
  const [explainerOpen, setExplainerOpen] = useState(false);

  return (
    <section className="chart-shell">
      <header>
        <div className="chart-title-group">
          <h2>{title}</h2>
          {note && <p>{note}</p>}
        </div>
        <div className="chart-header-actions">
          {action}
          {dataTable && (
            <button
              className="quiet chart-table-btn"
              onClick={() => setTableOpen((prev) => !prev)}
              aria-expanded={tableOpen}
              aria-controls={`${title.replace(/\s/g, "-")}-table`}
            >
              {tableOpen ? "Hide table" : "Show table ♿"}
            </button>
          )}
          <div className="chart-explainer-wrap">
            <button
              className="explainer-btn"
              aria-expanded={explainerOpen}
              aria-label={`How to read: ${title}`}
              onClick={() => setExplainerOpen((prev) => !prev)}
            >
              ?
            </button>
            {explainerOpen && (
              <aside
                className="chart-explainer"
                role="dialog"
                aria-modal="false"
                aria-label={`How to read ${title}`}
              >
                <button
                  className="icon-button explainer-close"
                  onClick={() => setExplainerOpen(false)}
                  aria-label="Close explainer"
                >
                  ×
                </button>
                {explainer}
              </aside>
            )}
          </div>
        </div>
      </header>

      {loading ? (
        <div style={{ height }}>
          <Skeleton rows={5} />
        </div>
      ) : tableOpen ? (
        <div
          id={`${title.replace(/\s/g, "-")}-table`}
          className="chart-data-table"
          role="region"
          aria-label={`Data table: ${title}`}
        >
          {dataTable ?? <p className="muted">No data table available for this visualisation.</p>}
        </div>
      ) : (
        <div
          className="chart-body"
          style={{ height }}
          role="img"
          aria-label={title}
        >
          {children}
        </div>
      )}
    </section>
  );
}
