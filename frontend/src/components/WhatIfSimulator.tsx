import { useState, useMemo } from "react";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, Legend,
} from "recharts";
import { ChartShell } from "./ChartShell";
import type { ApplicationSummary } from "../api/client";

export interface SimSystem {
  id: string;
  name: string;
  criticality: "Critical" | "High" | "Medium" | "Low";
  vulnerableCount: number;
  safeCount: number;
  dataLifespanYears: number; // X
  migrationYears: number; // Z
}

const DEFAULT_SIM_SYSTEMS: SimSystem[] = [
  {
    id: "app-1",
    name: "Payment Gateway Core",
    criticality: "Critical",
    vulnerableCount: 14,
    safeCount: 2,
    dataLifespanYears: 10,
    migrationYears: 2,
  },
  {
    id: "app-2",
    name: "Customer Identity & Access (IdP)",
    criticality: "Critical",
    vulnerableCount: 18,
    safeCount: 3,
    dataLifespanYears: 8,
    migrationYears: 1.5,
  },
  {
    id: "app-3",
    name: "Edge API Ingress / TLS Terminators",
    criticality: "High",
    vulnerableCount: 9,
    safeCount: 5,
    dataLifespanYears: 3,
    migrationYears: 1,
  },
  {
    id: "app-4",
    name: "Internal Document Store & Archives",
    criticality: "High",
    vulnerableCount: 12,
    safeCount: 1,
    dataLifespanYears: 15,
    migrationYears: 3,
  },
  {
    id: "app-5",
    name: "B2B Partner Webhook Dispatcher",
    criticality: "Medium",
    vulnerableCount: 6,
    safeCount: 4,
    dataLifespanYears: 5,
    migrationYears: 1,
  },
  {
    id: "app-6",
    name: "Analytics & Telemetry Collector",
    criticality: "Low",
    vulnerableCount: 4,
    safeCount: 12,
    dataLifespanYears: 2,
    migrationYears: 0.8,
  },
];

const COLORS = {
  P0: "var(--p0)",
  P1: "var(--p1)",
  P2: "var(--p2)",
  Safe: "#3fb950",
};

interface WhatIfSimulatorProps {
  initialSystems?: SimSystem[];
  loading?: boolean;
}

export function WhatIfSimulator({
  initialSystems,
  loading = false,
}: WhatIfSimulatorProps) {
  const [systems] = useState<SimSystem[]>(initialSystems ?? DEFAULT_SIM_SYSTEMS);
  const [selectedSystemIds, setSelectedSystemIds] = useState<Set<string>>(
    new Set(["app-1", "app-2", "app-3"]) // default top 3 selected
  );
  const [breakYearY, setBreakYearY] = useState<number>(2035);
  const [migrationSpeedZ, setMigrationSpeedZ] = useState<number>(2);
  const [simulated, setSimulated] = useState<boolean>(true);

  const toggleSelect = (id: string) => {
    setSelectedSystemIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectAll = () => setSelectedSystemIds(new Set(systems.map((s) => s.id)));
  const selectHighRisk = () =>
    setSelectedSystemIds(
      new Set(systems.filter((s) => s.criticality === "Critical" || s.criticality === "High").map((s) => s.id))
    );
  const clearSelection = () => setSelectedSystemIds(new Set());

  // Compute baseline posture vs simulated posture
  const results = useMemo(() => {
    const currentYear = new Date().getFullYear();
    let baseP0 = 0;
    let baseP1 = 0;
    let baseSafe = 0;
    let baseDeficitSystems = 0;

    let simP0 = 0;
    let simP1 = 0;
    let simSafe = 0;
    let simDeficitSystems = 0;

    systems.forEach((sys) => {
      const isSelected = selectedSystemIds.has(sys.id);
      const effectiveZ = isSelected ? Math.min(sys.migrationYears, migrationSpeedZ) : sys.migrationYears;
      const moscaBreach = currentYear + (breakYearY - currentYear - effectiveZ);

      // Baseline
      if (sys.criticality === "Critical") {
        baseP0 += sys.vulnerableCount;
      } else if (sys.criticality === "High") {
        baseP1 += sys.vulnerableCount;
      } else {
        baseP1 += Math.round(sys.vulnerableCount * 0.5);
      }
      baseSafe += sys.safeCount;
      if (currentYear + sys.dataLifespanYears + sys.migrationYears > breakYearY) {
        baseDeficitSystems++;
      }

      // Simulated
      if (isSelected) {
        // Selected systems migrate their vulnerable artefacts to safe
        simSafe += sys.vulnerableCount + sys.safeCount;
        // Remaining minor residual (e.g. 5% edge cases)
        const residual = Math.max(0, Math.floor(sys.vulnerableCount * 0.05));
        if (sys.criticality === "Critical") simP0 += residual;
        else simP1 += residual;

        // With accelerated migration Z, check breach
        if (currentYear + sys.dataLifespanYears + effectiveZ > breakYearY) {
          simDeficitSystems++;
        }
      } else {
        // Unmigrated systems retain vulnerability
        if (sys.criticality === "Critical") simP0 += sys.vulnerableCount;
        else simP1 += sys.vulnerableCount;
        simSafe += sys.safeCount;
        if (currentYear + sys.dataLifespanYears + sys.migrationYears > breakYearY) {
          simDeficitSystems++;
        }
      }
    });

    const totalBase = baseP0 + baseP1 + baseSafe || 1;
    const baseScore = Math.round((baseSafe / totalBase) * 100);

    const totalSim = simP0 + simP1 + simSafe || 1;
    const simScore = Math.round((simSafe / totalSim) * 100);

    const beforePieData = [
      { name: "P0 (Critical)", value: baseP0, color: COLORS.P0 },
      { name: "P1 (High)", value: baseP1, color: COLORS.P1 },
      { name: "Safe (PQC)", value: baseSafe, color: COLORS.Safe },
    ].filter((d) => d.value > 0);

    const afterPieData = [
      { name: "P0 (Critical)", value: simP0, color: COLORS.P0 },
      { name: "P1 (High)", value: simP1, color: COLORS.P1 },
      { name: "Safe (PQC)", value: simSafe, color: COLORS.Safe },
    ].filter((d) => d.value > 0);

    return {
      baseScore,
      simScore,
      scoreDelta: simScore - baseScore,
      baseP0,
      simP0,
      p0Delta: simP0 - baseP0,
      baseDeficitSystems,
      simDeficitSystems,
      deficitDelta: simDeficitSystems - baseDeficitSystems,
      beforePieData,
      afterPieData,
    };
  }, [systems, selectedSystemIds, breakYearY, migrationSpeedZ]);

  const dataTable = (
    <table className="data-table">
      <thead>
        <tr>
          <th>System</th>
          <th>Criticality</th>
          <th>Included in Simulation?</th>
          <th>Current Vuln Assets</th>
          <th>Data Life (X)</th>
          <th>Migration Time (Z)</th>
          <th>Post-Migration State</th>
        </tr>
      </thead>
      <tbody>
        {systems.map((s) => {
          const isSelected = selectedSystemIds.has(s.id);
          return (
            <tr key={s.id}>
              <td><strong>{s.name}</strong></td>
              <td>{s.criticality}</td>
              <td>{isSelected ? "✅ Migrated" : "❌ Unchanged"}</td>
              <td>{s.vulnerableCount} assets</td>
              <td>{s.dataLifespanYears} years</td>
              <td>{s.migrationYears} years</td>
              <td>
                {isSelected ? (
                  <span className="badge-p2">Migrated to PQC (Safe)</span>
                ) : (
                  <span className="badge-p0">Remains Vulnerable</span>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );

  return (
    <div className="whatif-simulator">
      {/* Simulation Scenario Controls */}
      <div className="sim-controls-panel">
        <div className="sim-header">
          <h3>Simulation Scenario Parameters</h3>
          <p className="sim-subtitle">
            Model the impact of proactive migration campaigns on overall organizational quantum readiness.
          </p>
        </div>

        <div className="sim-controls-grid">
          {/* Slider 1: Quantum Break Year Y */}
          <div className="sim-slider-group">
            <div className="sim-slider-label">
              <span>Cryptanalytically Relevant Quantum Computer (Y)</span>
              <strong>{breakYearY}</strong>
            </div>
            <input
              type="range"
              min={2028}
              max={2042}
              step={1}
              value={breakYearY}
              onChange={(e) => setBreakYearY(Number(e.target.value))}
              className="slider"
            />
            <div className="sim-slider-ticks">
              <span>2028 (Aggressive)</span>
              <span>2035 (Consensus)</span>
              <span>2042 (Conservative)</span>
            </div>
          </div>

          {/* Slider 2: Migration Acceleration (Z) */}
          <div className="sim-slider-group">
            <div className="sim-slider-label">
              <span>Accelerated Migration Duration (Z)</span>
              <strong>{migrationSpeedZ} years</strong>
            </div>
            <input
              type="range"
              min={0.5}
              max={5}
              step={0.5}
              value={migrationSpeedZ}
              onChange={(e) => setMigrationSpeedZ(Number(e.target.value))}
              className="slider"
            />
            <div className="sim-slider-ticks">
              <span>6 Months</span>
              <span>2 Years</span>
              <span>5 Years</span>
            </div>
          </div>
        </div>

        {/* Target Systems Selector */}
        <div className="sim-system-selection">
          <div className="sim-selector-top">
            <strong>Target Systems for Migration ({selectedSystemIds.size} of {systems.length} selected):</strong>
            <div className="button-group">
              <button className="button small secondary" onClick={selectAll}>Select All</button>
              <button className="button small secondary" onClick={selectHighRisk}>High/Critical Only</button>
              <button className="button small secondary" onClick={clearSelection}>Clear</button>
            </div>
          </div>

          <div className="sim-system-pills">
            {systems.map((sys) => {
              const isSelected = selectedSystemIds.has(sys.id);
              return (
                <button
                  key={sys.id}
                  className={`sim-system-pill ${isSelected ? "selected" : ""}`}
                  onClick={() => toggleSelect(sys.id)}
                  type="button"
                >
                  <span className="pill-check">{isSelected ? "✓" : "+"}</span>
                  <span className="pill-name">{sys.name}</span>
                  <span className={`pill-badge badge-${sys.criticality.toLowerCase()}`}>
                    {sys.vulnerableCount} vuln
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Delta Metric Tiles */}
      <div className="sim-delta-grid">
        <div className="metric">
          <span className="metric-label">Quantum Readiness Score</span>
          <div className="metric-score-delta">
            <span className="score-before">{results.baseScore}%</span>
            <span className="delta-arrow">➔</span>
            <span className="score-after">{results.simScore}%</span>
          </div>
          <span className="metric-sub success">+{results.scoreDelta}% improvement</span>
        </div>

        <div className="metric">
          <span className="metric-label">Critical (P0) Assets</span>
          <div className="metric-score-delta">
            <span className="score-before">{results.baseP0}</span>
            <span className="delta-arrow">➔</span>
            <span className="score-after">{results.simP0}</span>
          </div>
          <span className="metric-sub success">{results.p0Delta} eliminated</span>
        </div>

        <div className="metric">
          <span className="metric-label">Mosca Deficit Violations</span>
          <div className="metric-score-delta">
            <span className="score-before">{results.baseDeficitSystems}</span>
            <span className="delta-arrow">➔</span>
            <span className="score-after">{results.simDeficitSystems}</span>
          </div>
          <span className="metric-sub success">{results.deficitDelta} breach risks avoided</span>
        </div>
      </div>

      {/* Before / After ChartShell */}
      <ChartShell
        title="Simulated Posture Projection: Before vs After"
        explainer={
          <div>
            <p><strong>How to use the What-If Simulator:</strong></p>
            <p>
              The What-If Simulator lets security architects test scenarios before committing engineering resources:
            </p>
            <ul>
              <li>
                <strong>Target System Selection:</strong> Select systems scheduled for migration.
                Their vulnerable cryptographic primitives will be converted to post-quantum standards in the model.
              </li>
              <li>
                <strong>CRQC Arrival (Y):</strong> Adjust when a cryptanalytically relevant quantum computer is expected.
                Earlier dates increase Mosca inequality pressure.
              </li>
              <li>
                <strong>Accelerated Migration (Z):</strong> Simulates the outcome of dedicated tooling and headcount
                shortening transition windows.
              </li>
            </ul>
            <p>
              <em>Simulations are volatile and exploratory — no production configuration or persistent state is changed.</em>
            </p>
          </div>
        }
        note="Modelled comparison of risk distribution under the simulated migration campaign."
        dataTable={dataTable}
        loading={loading}
        height="auto"
      >
        <div className="sim-charts-compare">
          <div className="sim-chart-box">
            <h4>Current Baseline Posture</h4>
            <div style={{ width: "100%", height: 240 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={results.beforePieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={3}
                  >
                    {results.beforePieData.map((entry, idx) => (
                      <Cell key={idx} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip
                    contentStyle={{ background: "var(--surface)", border: "1px solid var(--line)" }}
                  />
                  <Legend
                    verticalAlign="bottom"
                    height={36}
                    formatter={(val) => <span style={{ color: "var(--text)", fontSize: 12 }}>{val}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="sim-chart-caption">
              Overall Score: <strong>{results.baseScore}%</strong> · {results.baseP0} Critical Vulns
            </div>
          </div>

          <div className="sim-compare-divider">
            <div className="arrow-circle">➔</div>
          </div>

          <div className="sim-chart-box highlight">
            <h4>Simulated Post-Migration Posture</h4>
            <div style={{ width: "100%", height: 240 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={results.afterPieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={3}
                  >
                    {results.afterPieData.map((entry, idx) => (
                      <Cell key={idx} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip
                    contentStyle={{ background: "var(--surface)", border: "1px solid var(--line)" }}
                  />
                  <Legend
                    verticalAlign="bottom"
                    height={36}
                    formatter={(val) => <span style={{ color: "var(--text)", fontSize: 12 }}>{val}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="sim-chart-caption">
              Projected Score: <strong className="success">{results.simScore}%</strong> · {results.simP0} Critical Vulns
            </div>
          </div>
        </div>
      </ChartShell>
    </div>
  );
}
