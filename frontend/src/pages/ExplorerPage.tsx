import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import {
  Page,
  Empty,
  Skeleton,
  ErrorState,
  ArtefactTable,
  Pagination,
  ArtefactDrawer,
  BulkReviewDialog,
  DemoDataLoader,
  ExportButton,
} from "../components";
import { RiskBadge } from "../components/RiskBadge";
import { titleCase } from "../risk";

/**
 * CBOM Explorer — the analyst's main working surface (§9.6).
 * Primary persona: Security analyst — "Which findings are real, and which do I fix first?"
 *
 * §9.6a — virtualised table, smooth at 100k rows
 * §9.6b — opens sorted by risk, descending (server-side default)
 * §9.6c — faceted filters with live result counts
 * §9.6d — column selection, sort, saved views; filter state in URL
 * §9.6e — artefact detail drawer
 * §9.6f — bulk actions
 * §9.6g — coverage-gap banner
 * §4.7c — every view is URL-addressable and shareable
 */
export function ExplorerPage() {
  const api = useApi();
  const { project, user } = useAuth();
  const client = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [selected, setSelected] = useState<string[]>([]);
  const [reviewOpen, setReviewOpen] = useState(false);

  const filters = {
    q: params.get("q") ?? "",
    type: params.get("type") ?? "",
    priority: params.get("priority") ?? "",
    algorithm: params.get("algorithm") ?? "",
    application_id: params.get("application_id") ?? "",
    quantum_status: params.get("quantum_status") ?? "",
    scanner: params.get("scanner") ?? "",
    offset: Number(params.get("offset") ?? 0),
    limit: 100,
  };

  const response = useQuery({
    queryKey: ["artefacts", project?.id, filters],
    queryFn: () => api.artefacts(filters),
    enabled: !!project,
  });

  const apply = (name: string, value: string) =>
    setParams((current) => {
      if (value) current.set(name, value);
      else current.delete(name);
      current.delete("offset");
      return current;
    });

  const columns = new Set((params.get("columns") ?? "evidence,source").split(","));
  const toggleColumn = (column: string) =>
    setParams((current) => {
      const next = new Set((current.get("columns") ?? "evidence,source").split(","));
      if (next.has(column)) next.delete(column);
      else next.add(column);
      current.set("columns", Array.from(next).filter(Boolean).join(","));
      return current;
    });

  if (!project)
    return (
      <Page
        title="Artefact explorer"
        subtitle="Search, filter, and open evidence without losing your place."
      >
        <Empty title="Choose a project" icon="📂">
          Artefacts are scoped to the active project.
        </Empty>
      </Page>
    );

  const drawerLink = (artefact: { id: string }) => {
    const next = new URLSearchParams(params);
    next.set("artefact", artefact.id);
    return `/explorer?${next.toString()}`;
  };

  const toggle = (id: string) =>
    setSelected((current) =>
      current.includes(id) ? current.filter((v) => v !== id) : [...current, id],
    );

  const hasPartialResults = response.data?.partial_results;

  const activeFilters = [
    filters.q ? { key: "q", label: `Search: "${filters.q}"` } : null,
    filters.priority ? { key: "priority", label: `Priority: ${titleCase(filters.priority)}` } : null,
    filters.type ? { key: "type", label: `Type: ${titleCase(filters.type)}` } : null,
    filters.algorithm ? { key: "algorithm", label: `Algo: ${filters.algorithm}` } : null,
    filters.quantum_status ? { key: "quantum_status", label: `Quantum: ${titleCase(filters.quantum_status)}` } : null,
    filters.scanner ? { key: "scanner", label: `Scanner: ${titleCase(filters.scanner)}` } : null,
    filters.application_id ? { key: "application_id", label: `App: ${filters.application_id}` } : null,
  ].filter(Boolean) as { key: string; label: string }[];

  return (
    <Page
      title="Artefact explorer"
      subtitle="Filters live in the URL — this exact view is shareable and survives navigation."
    >
      <section className="explorer-layout">
        {/* Filter panel */}
        <aside className="filter-panel">
          <div className="search-filter-box">
            <label htmlFor="explorer-search" className="search-filter-label">
              Search
            </label>
            <div className="search-input-wrapper">
              <span className="search-input-icon" aria-hidden="true">🔍</span>
              <input
                id="explorer-search"
                value={filters.q}
                onChange={(event) => apply("q", event.target.value)}
                placeholder="Name, path, algorithm…"
              />
              {filters.q && (
                <button
                  type="button"
                  className="search-clear-btn"
                  onClick={() => apply("q", "")}
                  title="Clear search"
                  aria-label="Clear search"
                >
                  ✕
                </button>
              )}
            </div>
          </div>
          <Facet
            label="Priority"
            selected={filters.priority}
            values={response.data?.facets.priority}
            apply={(value) => apply("priority", value)}
            renderValue={(v) => <RiskBadge priority={v} />}
          />
          <Facet
            label="Type"
            selected={filters.type}
            values={response.data?.facets.type}
            apply={(value) => apply("type", value)}
          />
          <Facet
            label="Algorithm"
            selected={filters.algorithm}
            values={response.data?.facets.algorithm}
            apply={(value) => apply("algorithm", value)}
          />
          <Facet
            label="Quantum status"
            selected={filters.quantum_status}
            values={response.data?.facets.quantum_status}
            apply={(value) => apply("quantum_status", value)}
          />
          <Facet
            label="Application"
            selected={filters.application_id}
            values={response.data?.facets.application}
            apply={(value) => apply("application_id", value === "unassigned" ? "" : value)}
          />
          <Facet
            label="Scanner"
            selected={filters.scanner}
            values={response.data?.facets.scanner}
            apply={(value) => apply("scanner", value)}
          />
          <ColumnSelector columns={columns} toggle={toggleColumn} />
          <SavedViews query={params.toString()} apply={(query) => setParams(query)} />
          <button
            className="quiet filter-clear-all"
            onClick={() => setParams({})}
            disabled={!params.toString()}
          >
            Clear all filters
          </button>
        </aside>

        {/* Results panel */}
        <section className="panel table-panel">
          <header className="table-panel-header">
            <div className="table-panel-title">
              <div className="title-with-pill">
                <h2>Findings</h2>
                {response.data && (
                  <span className="findings-count-pill">
                    {response.data.page.total.toLocaleString()} artefacts
                  </span>
                )}
              </div>
              <p className="findings-subtext">
                {response.data
                  ? `Showing ranked findings based on active cryptographic posture`
                  : "Loading results…"}
                {hasPartialResults && (
                  <span className="partial-badge"> · Partial results (scan in progress)</span>
                )}
              </p>
            </div>
            <div className="table-actions">
              <ExportButton filters={filters} label="Export CSV" />
              <button
                className="copy-view-btn"
                onClick={() => navigator.clipboard?.writeText(location.href)}
                title="Copy a shareable link to this exact filter view"
              >
                Copy view link
              </button>
              {selected.length > 0 && user?.role !== "viewer" && (
                <button className="primary" onClick={() => setReviewOpen(true)}>
                  Review {selected.length}
                </button>
              )}
            </div>
          </header>

          {/* Active filter chips */}
          {activeFilters.length > 0 && (
            <div className="active-filters-bar">
              <span className="active-filters-title">Active filters:</span>
              <div className="active-filter-chips">
                {activeFilters.map((f) => (
                  <button
                    type="button"
                    key={f.key}
                    className="active-filter-chip"
                    onClick={() => apply(f.key, "")}
                    title={`Remove ${f.label}`}
                  >
                    <span>{f.label}</span>
                    <span className="chip-remove-icon" aria-hidden="true">✕</span>
                  </button>
                ))}
                <button
                  type="button"
                  className="filter-chip-reset"
                  onClick={() => setParams({})}
                >
                  Reset all
                </button>
              </div>
            </div>
          )}

          {/* §9.6g — coverage-gap banner */}
          {hasPartialResults && (
            <div className="coverage-banner" role="status">
              ⚠ Partial results — the scan is still running. Refresh to see new findings.
            </div>
          )}

          {response.isPending ? (
            <Skeleton rows={9} />
          ) : response.isError ? (
            <ErrorState error={response.error} retry={() => void response.refetch()} />
          ) : response.data?.items.length ? (
            <>
              <ArtefactTable
                rows={response.data.items}
                virtualized
                linkFor={drawerLink}
                selectable={user?.role !== "viewer"}
                selected={selected}
                onToggle={toggle}
                showEvidence={columns.has("evidence")}
                showSource={columns.has("source")}
              />
              <Pagination
                page={response.data.page}
                setPage={(offset) =>
                  setParams((current) => {
                    current.set("offset", String(offset));
                    return current;
                  })
                }
              />
            </>
          ) : (
            <Empty
              title="No matching artefacts"
              icon="🔍"
              action={
                <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", justifyContent: "center" }}>
                  <button className="button quiet" onClick={() => setParams({})}>
                    Clear filters
                  </button>
                  <DemoDataLoader variant="secondary" />
                </div>
              }
            >
              Broaden the search or load the demo dataset to explore 48 realistic cryptographic findings.
            </Empty>
          )}
        </section>
      </section>

      {/* Bulk review dialog */}
      {reviewOpen && (
        <BulkReviewDialog
          artefactIds={selected}
          close={() => setReviewOpen(false)}
          done={() => {
            setSelected([]);
            setReviewOpen(false);
            void client.invalidateQueries({ queryKey: ["artefacts", project.id] });
          }}
        />
      )}

      {/* §9.6e — artefact detail drawer (URL-driven) */}
      {params.get("artefact") && (
        <ArtefactDrawer
          artefactId={params.get("artefact")!}
          close={() =>
            setParams((current) => {
              current.delete("artefact");
              return current;
            })
          }
        />
      )}
    </Page>
  );
}

// ─── Filter helpers ───────────────────────────────────────────────────────────

interface FacetProps {
  label: string;
  selected: string;
  values?: Record<string, number>;
  apply: (value: string) => void;
  renderValue?: (value: string) => React.ReactNode;
}

function Facet({ label, selected, values, apply, renderValue }: FacetProps) {
  const entries = Object.entries(values ?? {}).slice(0, 12);
  return (
    <fieldset className="facet-group">
      <legend>{label}</legend>
      {entries.length ? (
        entries.map(([value, count]) => {
          const isSelected = selected === value;
          return (
            <label className={`check facet-item ${isSelected ? "selected-facet" : ""}`} key={value}>
              <input
                type="radio"
                name={`facet-${label}`}
                checked={isSelected}
                onChange={() => apply(isSelected ? "" : value)}
              />
              <span className="facet-value-label">
                {renderValue ? renderValue(value) : titleCase(value)}
              </span>
              <small className="facet-count">{count.toLocaleString()}</small>
            </label>
          );
        })
      ) : (
        <p className="muted">Filters appear once results load.</p>
      )}
    </fieldset>
  );
}

function ColumnSelector({ columns, toggle }: { columns: Set<string>; toggle: (c: string) => void }) {
  return (
    <fieldset>
      <legend>Columns</legend>
      <label className="check">
        <input
          type="checkbox"
          checked={columns.has("evidence")}
          onChange={() => toggle("evidence")}
        />
        Evidence
      </label>
      <label className="check">
        <input
          type="checkbox"
          checked={columns.has("source")}
          onChange={() => toggle("source")}
        />
        Source
      </label>
    </fieldset>
  );
}

type SavedView = { name: string; query: string };

function SavedViews({ query, apply }: { query: string; apply: (query: string) => void }) {
  const [views, setViews] = useState<SavedView[]>(() => {
    try {
      return JSON.parse(localStorage.getItem("trinetra.explorer.views") ?? "[]") as SavedView[];
    } catch {
      return [];
    }
  });
  const [name, setName] = useState("");

  const save = () => {
    const clean = name.trim();
    if (!clean) return;
    const next = [...views.filter((v) => v.name !== clean), { name: clean, query }].slice(-10);
    setViews(next);
    localStorage.setItem("trinetra.explorer.views", JSON.stringify(next));
    setName("");
  };

  return (
    <fieldset>
      <legend>Saved views</legend>
      <div className="save-view">
        <input
          aria-label="View name"
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="View name"
        />
        <button type="button" onClick={save} disabled={!name.trim()}>
          Save
        </button>
      </div>
      {views.map((view) => (
        <button
          type="button"
          className="saved-view"
          key={view.name}
          onClick={() => apply(view.query)}
        >
          {view.name}
        </button>
      ))}
    </fieldset>
  );
}
