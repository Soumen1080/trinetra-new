import { useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { ChartShell } from "./ChartShell";

export interface MigrationItem {
  id: string;
  name: string;
  applicationId?: string;
  wave: "Wave 1 (2025–2026)" | "Wave 2 (2027–2028)" | "Wave 3 (2029–2032)";
  startYear: number;
  endYear: number;
  breachYear: number; // Mosca breach date
  effortWeeks: number;
  costEstimate: number; // in USD
  algorithm: string;
  replacementAlgo: string;
  priority: "P0" | "P1" | "P2";
}

const DEFAULT_MIGRATION_PLAN: MigrationItem[] = [
  {
    id: "mig-1",
    name: "Payment Gateway Core",
    wave: "Wave 1 (2025–2026)",
    startYear: 2025.2,
    endYear: 2026.5,
    breachYear: 2029,
    effortWeeks: 24,
    costEstimate: 75000,
    algorithm: "RSA-2048",
    replacementAlgo: "ML-KEM-768",
    priority: "P0",
  },
  {
    id: "mig-2",
    name: "Customer Auth Service",
    wave: "Wave 1 (2025–2026)",
    startYear: 2025.5,
    endYear: 2026.8,
    breachYear: 2028,
    effortWeeks: 32,
    costEstimate: 110000,
    algorithm: "ECDSA-P256",
    replacementAlgo: "ML-DSA-65",
    priority: "P0",
  },
  {
    id: "mig-3",
    name: "Public Edge Ingress (TLS)",
    wave: "Wave 1 (2025–2026)",
    startYear: 2025.0,
    endYear: 2026.0,
    breachYear: 2027,
    effortWeeks: 16,
    costEstimate: 45000,
    algorithm: "ECDHE-RSA",
    replacementAlgo: "X25519MLKEM768",
    priority: "P0",
  },
  {
    id: "mig-4",
    name: "Internal Document Archive",
    wave: "Wave 2 (2027–2028)",
    startYear: 2027.0,
    endYear: 2028.5,
    breachYear: 2031,
    effortWeeks: 40,
    costEstimate: 130000,
    algorithm: "RSA-3072",
    replacementAlgo: "ML-DSA-87",
    priority: "P1",
  },
  {
    id: "mig-5",
    name: "B2B Partner API Gateway",
    wave: "Wave 2 (2027–2028)",
    startYear: 2027.2,
    endYear: 2028.8,
    breachYear: 2030,
    effortWeeks: 28,
    costEstimate: 95000,
    algorithm: "ECDH-P384",
    replacementAlgo: "ML-KEM-1024",
    priority: "P1",
  },
  {
    id: "mig-6",
    name: "Telemetry & Logs Pipeline",
    wave: "Wave 3 (2029–2032)",
    startYear: 2029.0,
    endYear: 2030.5,
    breachYear: 2035,
    effortWeeks: 18,
    costEstimate: 50000,
    algorithm: "AES-128-GCM",
    replacementAlgo: "AES-256-GCM",
    priority: "P2",
  },
  {
    id: "mig-7",
    name: "Legacy VPN Concentrator",
    wave: "Wave 3 (2029–2032)",
    startYear: 2029.5,
    endYear: 2031.5,
    breachYear: 2030, // At risk: breach year before end year!
    effortWeeks: 36,
    costEstimate: 120000,
    algorithm: "DH-2048",
    replacementAlgo: "ML-KEM-768",
    priority: "P1",
  },
];

const WAVES = [
  "Wave 1 (2025–2026)",
  "Wave 2 (2027–2028)",
  "Wave 3 (2029–2032)",
] as const;

const MIN_YEAR = 2025;
const MAX_YEAR = 2035;
const TOTAL_YEAR_SPAN = MAX_YEAR - MIN_YEAR;

interface MigrationPlannerProps {
  initialItems?: MigrationItem[];
  loading?: boolean;
}

export function MigrationPlanner({ initialItems, loading = false }: MigrationPlannerProps) {
  const [items, setItems] = useState<MigrationItem[]>(initialItems ?? DEFAULT_MIGRATION_PLAN);
  const [draggedId, setDraggedId] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<string>("all");

  const rollups = useMemo(() => {
    const totalWeeks = items.reduce((acc, it) => acc + it.effortWeeks, 0);
    const totalCost = items.reduce((acc, it) => acc + it.costEstimate, 0);
    const atRiskBreach = items.filter((it) => it.endYear >= it.breachYear).length;
    return {
      totalSystems: items.length,
      totalWeeks,
      totalCost,
      atRiskBreach,
    };
  }, [items]);

  const handleDragStart = (id: string) => {
    setDraggedId(id);
  };

  const handleDropOnWave = (targetWave: typeof WAVES[number]) => {
    if (!draggedId) return;
    setItems((prev) =>
      prev.map((item) => {
        if (item.id === draggedId) {
          let start = item.startYear;
          let end = item.endYear;
          const duration = end - start;
          if (targetWave === "Wave 1 (2025–2026)") {
            start = 2025.2;
            end = 2025.2 + duration;
          } else if (targetWave === "Wave 2 (2027–2028)") {
            start = 2027.0;
            end = 2027.0 + duration;
          } else {
            start = 2029.0;
            end = 2029.0 + duration;
          }
          return { ...item, wave: targetWave, startYear: start, endYear: end };
        }
        return item;
      })
    );
    setDraggedId(null);
  };

  const filteredItems = useMemo(() => {
    if (activeFilter === "all") return items;
    return items.filter((it) => it.wave === activeFilter);
  }, [items, activeFilter]);

  const dataTable = (
    <table className="data-table">
      <thead>
        <tr>
          <th>System</th>
          <th>Wave</th>
          <th>Current Algo</th>
          <th>Proposed Algo</th>
          <th>Planned Window</th>
          <th>Mosca Breach</th>
          <th>Effort</th>
          <th>Est. Cost</th>
          <th>Breach Risk</th>
        </tr>
      </thead>
      <tbody>
        {items.map((item) => {
          const isBreachRisk = item.endYear >= item.breachYear;
          return (
            <tr key={item.id} className={isBreachRisk ? "row-danger" : ""}>
              <td><strong>{item.name}</strong></td>
              <td>{item.wave}</td>
              <td><code>{item.algorithm}</code></td>
              <td><code>{item.replacementAlgo}</code></td>
              <td>{item.startYear.toFixed(1)} – {item.endYear.toFixed(1)}</td>
              <td>{item.breachYear}</td>
              <td>{item.effortWeeks} person-weeks</td>
              <td>${item.costEstimate.toLocaleString()}</td>
              <td>
                {isBreachRisk ? (
                  <span className="badge-p0">⚠ Breach ({item.breachYear}) before completion!</span>
                ) : (
                  <span className="badge-p2">On track</span>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );

  return (
    <div className="migration-planner">
      {/* Rollup Summary Tiles */}
      <div className="planner-rollups">
        <div className="metric">
          <span className="metric-label">Planned Systems</span>
          <span className="metric-value">{rollups.totalSystems}</span>
        </div>
        <div className="metric">
          <span className="metric-label">Total Engineering Effort</span>
          <span className="metric-value">{rollups.totalWeeks} <small>weeks</small></span>
          <span className="metric-sub">{Math.round(rollups.totalWeeks / 4.3)} person-months</span>
        </div>
        <div className="metric">
          <span className="metric-label">Estimated Migration Cost</span>
          <span className="metric-value">${(rollups.totalCost / 1000).toFixed(0)}k</span>
          <span className="metric-sub">Blended contractor/FTE rate</span>
        </div>
        <div className={`metric ${rollups.atRiskBreach > 0 ? "metric-p0" : "metric-p2"}`}>
          <span className="metric-label">Breach Deficit Systems</span>
          <span className="metric-value">{rollups.atRiskBreach}</span>
          <span className="metric-sub">
            {rollups.atRiskBreach > 0 ? "Planned end ≥ Mosca breach date" : "All planned before breach"}
          </span>
        </div>
      </div>

      <ChartShell
        title="Migration Roadmap & Wave Gantt"
        explainer={
          <div>
            <p><strong>How to read this Gantt roadmap:</strong></p>
            <p>
              Each row represents a system being transitioned to Post-Quantum Cryptography (PQC).
              The horizontal teal/blue bar shows the planned migration window.
            </p>
            <p>
              The <strong style={{ color: "var(--p0)" }}>vertical red marker</strong> indicates the
              system's <em>Mosca Breach Date</em> (when quantum break occurs before data lifespan ends).
            </p>
            <p>
              <strong>Drag and drop:</strong> Grab any system card and drop it into a different wave to reprioritise.
              The dates and wave totals update automatically.
            </p>
            <p>
              If a system's planned end date extends past its breach date, it is flagged with a warning banner.
            </p>
          </div>
        }
        note="Gantt chart by wave. Drag items between waves to reprioritise. Red indicator shows Mosca breach deadline."
        dataTable={dataTable}
        loading={loading}
        height="auto"
        action={
          <div className="button-group" style={{ display: "flex", gap: "0.5rem" }}>
            <button
              className={`button ${activeFilter === "all" ? "primary" : "secondary"}`}
              onClick={() => setActiveFilter("all")}
            >
              All Waves
            </button>
            {WAVES.map((wave) => (
              <button
                key={wave}
                className={`button ${activeFilter === wave ? "primary" : "secondary"}`}
                onClick={() => setActiveFilter(wave)}
              >
                {wave.split(" ")[0]}
              </button>
            ))}
          </div>
        }
      >
        <div className="gantt-container">
          {/* Gantt Header Timeline Scale */}
          <div className="gantt-scale">
            <div className="gantt-col-name">System & Wave</div>
            <div className="gantt-timeline-header">
              {Array.from({ length: TOTAL_YEAR_SPAN + 1 }).map((_, i) => {
                const year = MIN_YEAR + i;
                return (
                  <div key={year} className="gantt-scale-year">
                    {year}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Waves and Rows */}
          {WAVES.map((wave) => {
            if (activeFilter !== "all" && activeFilter !== wave) return null;
            const waveItems = filteredItems.filter((it) => it.wave === wave);
            const waveWeeks = waveItems.reduce((sum, it) => sum + it.effortWeeks, 0);
            const waveCost = waveItems.reduce((sum, it) => sum + it.costEstimate, 0);

            return (
              <div
                key={wave}
                className="gantt-wave-section"
                onDragOver={(e) => e.preventDefault()}
                onDrop={() => handleDropOnWave(wave)}
              >
                <div className="gantt-wave-header">
                  <div className="wave-title-group">
                    <span className="wave-title">{wave}</span>
                    <span className="wave-meta">
                      {waveItems.length} systems · {waveWeeks} person-weeks · ${(waveCost / 1000).toFixed(0)}k est.
                    </span>
                  </div>
                  <span className="wave-drop-hint">Drop here to move into {wave.split(" ")[0]}</span>
                </div>

                {waveItems.length === 0 ? (
                  <div className="gantt-empty-wave">No systems scheduled in this wave. Drag an item here.</div>
                ) : (
                  waveItems.map((item) => {
                    const startOffset = Math.max(0, item.startYear - MIN_YEAR);
                    const duration = Math.max(0.2, item.endYear - item.startYear);
                    const leftPercent = (startOffset / TOTAL_YEAR_SPAN) * 100;
                    const widthPercent = (duration / TOTAL_YEAR_SPAN) * 100;

                    const breachOffset = Math.max(0, item.breachYear - MIN_YEAR);
                    const breachPercent = (breachOffset / TOTAL_YEAR_SPAN) * 100;
                    const isBreachRisk = item.endYear >= item.breachYear;

                    return (
                      <div
                        key={item.id}
                        className={`gantt-row ${draggedId === item.id ? "dragging" : ""}`}
                        draggable
                        onDragStart={() => handleDragStart(item.id)}
                        onDragEnd={() => setDraggedId(null)}
                      >
                        <div className="gantt-row-label">
                          <span className="drag-handle" title="Drag to reorder/reassign wave">
                            ⋮⋮
                          </span>
                          <div className="gantt-row-info">
                            <span className="gantt-row-name">
                              {item.name}
                              {isBreachRisk && <span className="warning-dot" title="Planned end ≥ Mosca breach date">⚠</span>}
                            </span>
                            <span className="gantt-row-sub">
                              <code>{item.algorithm}</code> → <span className="pqc-rec">{item.replacementAlgo}</span>
                            </span>
                          </div>
                        </div>

                        <div className="gantt-timeline-track">
                          {/* Grid background markers */}
                          {Array.from({ length: TOTAL_YEAR_SPAN }).map((_, i) => (
                            <div key={i} className="gantt-grid-cell" />
                          ))}

                          {/* Planned migration bar */}
                          <div
                            className={`gantt-bar ${isBreachRisk ? "bar-urgent" : "bar-normal"}`}
                            style={{
                              left: `${leftPercent}%`,
                              width: `${Math.min(100 - leftPercent, widthPercent)}%`,
                            }}
                            title={`Planned: ${item.startYear.toFixed(1)} – ${item.endYear.toFixed(1)} (${item.effortWeeks} wks)`}
                          >
                            <span className="gantt-bar-label">
                              {item.effortWeeks}w · ${Math.round(item.costEstimate / 1000)}k
                            </span>
                          </div>

                          {/* Mosca Breach Marker */}
                          {breachPercent <= 100 && (
                            <div
                              className="gantt-breach-marker"
                              style={{ left: `${breachPercent}%` }}
                              title={`Mosca Breach Date: ${item.breachYear}`}
                            >
                              <div className="breach-flag">Breach {item.breachYear}</div>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            );
          })}
        </div>
      </ChartShell>
    </div>
  );
}
