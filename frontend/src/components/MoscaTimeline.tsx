import { useState, useMemo } from "react";
import { Link } from "react-router-dom";
import {
  ComposedChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ReferenceLine, ReferenceArea, Legend, ResponsiveContainer,
} from "recharts";
import type { MoscaTimeline as MoscaTimelineData } from "../api/client";
import { ChartShell } from "./ChartShell";

const SCENARIO_YEARS: Record<string, number> = {
  "2030": 2030,
  "2035": 2035,
  "2040": 2040,
};

interface MoscaTimelineProps {
  data: MoscaTimelineData[];
  loading?: boolean;
}

/**
 * 10.1 — Mosca timeline visualiser.
 *
 * For each system: shows X (data life), Z (migration time) as stacked bars from today,
 * and a Y reference line for the selected quantum-break scenario.
 * The overshoot region (where X+Z > Y) is shaded red — these systems need urgent action.
 *
 * Interactive Y-slider: 2030 / 2035 / 2040 / custom — bars don't change, Y line moves.
 */
export function MoscaTimeline({ data, loading = false }: MoscaTimelineProps) {
  const thisYear = new Date().getFullYear();
  const [scenarioKey, setScenarioKey] = useState<string>("2035");
  const [customYear, setCustomYear] = useState<number>(2035);

  const yYear = scenarioKey === "custom" ? customYear : SCENARIO_YEARS[scenarioKey];

  /** Transform data into recharts format: each row is one application */
  const chartData = useMemo(() =>
    data
      .filter((row) => row.x_years != null || row.z_years != null)
      .map((row) => ({
        name: row.application_name.length > 20
          ? row.application_name.slice(0, 18) + "…"
          : row.application_name,
        fullName: row.application_name,
        app_id: row.application_id,
        xYears: row.x_years ?? 0,
        zYears: row.z_years ?? 0,
        yYear: yYear,
        deadline: row.migration_deadline_year,
        overshoot: (row.x_years ?? 0) > (yYear - thisYear - (row.z_years ?? 0)),
      })),
    [data, yYear, thisYear]);

  const dataTable = (
    <table>
      <thead>
        <tr><th>System</th><th>Data life (X)</th><th>Migration time (Z)</th><th>Deadline (Y−Z)</th><th>Overshoot?</th></tr>
      </thead>
      <tbody>
        {data.map((row) => (
          <tr key={row.application_id}>
            <td><Link to={`/explorer?application_id=${row.application_id}`}>{row.application_name}</Link></td>
            <td>{row.x_years != null ? `${row.x_years} yr` : "Unknown"}</td>
            <td>{row.z_years != null ? `${row.z_years} yr` : "Unknown"}</td>
            <td>{row.migration_deadline_year ?? "Needs context"}</td>
            <td>{(row.x_years ?? 0) > (yYear - thisYear - (row.z_years ?? 0)) ? "⚠ Yes" : "✅ No"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );

  return (
    <ChartShell
      title="Mosca Timeline"
      explainer={
        <div>
          <p><strong>How to read this chart:</strong></p>
          <p>Each row is one system. The <strong>blue bar</strong> (X) is how long its data must stay secret. The <strong>teal bar</strong> (Z) is how long migration will take.</p>
          <p>The <strong>dashed vertical line</strong> is Y — when a quantum computer could break the algorithm under the selected scenario.</p>
          <p>If a system's bars extend past Y, it is in the <span style={{ color: "var(--p0)" }}>red overshoot zone</span> — migration must start immediately or data is at risk. Mosca's rule: if X + Z &gt; Y, act now.</p>
          <p>Use the scenario slider to model optimistic (2040) or pessimistic (2030) timelines.</p>
        </div>
      }
      note="Each row is one system. The red zone means X+Z > Y — act immediately."
      dataTable={dataTable}
      loading={loading}
      height={Math.max(240, chartData.length * 52 + 60)}
    >
      {/* Scenario Y-slider */}
      <div className="timeline-controls">
        <span>Quantum-break scenario (Y):</span>
        {Object.keys(SCENARIO_YEARS).map((key) => (
          <button
            key={key}
            className={scenarioKey === key ? "scenario-btn active" : "scenario-btn"}
            onClick={() => setScenarioKey(key)}
          >
            {key}
          </button>
        ))}
        <button
          className={scenarioKey === "custom" ? "scenario-btn active" : "scenario-btn"}
          onClick={() => setScenarioKey("custom")}
        >
          Custom
        </button>
        {scenarioKey === "custom" && (
          <input
            type="number"
            min={thisYear}
            max={thisYear + 30}
            value={customYear}
            onChange={(event) => setCustomYear(Number(event.target.value))}
            className="year-input"
            aria-label="Custom quantum-break year"
          />
        )}
        <span className="scenario-label">Y = {yYear}</span>
      </div>

      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart
          layout="vertical"
          data={chartData}
          margin={{ top: 0, right: 40, left: 0, bottom: 0 }}
        >
          <CartesianGrid horizontal={false} strokeDasharray="3 3" stroke="var(--line)" />
          <XAxis
            type="number"
            domain={[0, Math.max(yYear - thisYear + 10, 20)]}
            tickFormatter={(v: number) => `${v}y`}
            tick={{ fill: "var(--muted)", fontSize: 11 }}
          />
          <YAxis
            type="category"
            dataKey="name"
            width={130}
            tick={{ fill: "var(--text-2)", fontSize: 11 }}
          />
          <Tooltip
            formatter={(value: unknown, name: unknown) => [
              `${String(value ?? 0)} years`,
              name === "xYears" ? "Data life (X)" : "Migration time (Z)",
            ]}
            contentStyle={{ background: "var(--surface)", border: "1px solid var(--line)", borderRadius: "6px" }}
            labelStyle={{ color: "var(--text)", fontWeight: 700 }}
          />
          <Legend
            formatter={(value: string) => value === "xYears" ? "Data life (X)" : "Migration time (Z)"}
            wrapperStyle={{ fontSize: 12 }}
          />
          {/* Overshoot region */}
          <ReferenceArea
            x1={yYear - thisYear}
            x2={Math.max(yYear - thisYear + 10, 20)}
            fill="var(--p0)"
            fillOpacity={0.12}
          />
          {/* Y: quantum-break scenario line */}
          <ReferenceLine
            x={yYear - thisYear}
            stroke="var(--p0)"
            strokeDasharray="6 3"
            label={{ value: `Y=${yYear}`, position: "top", fill: "var(--p0)", fontSize: 11 }}
          />
          <Bar dataKey="xYears" name="xYears" stackId="a" fill="var(--brand)" radius={[0, 0, 0, 0]} />
          <Bar dataKey="zYears" name="zYears" stackId="a" fill="var(--p2)" radius={[0, 3, 3, 0]} />
        </ComposedChart>
      </ResponsiveContainer>
    </ChartShell>
  );
}

/** Shown when the API returns no Mosca data */
export function MoscaTimelineEmpty() {
  return (
    <ChartShell
      title="Mosca Timeline"
      explainer={<p>No Mosca context has been set. Complete the assessment context for your systems to populate this timeline.</p>}
      note="Run assessments to populate."
      loading={false}
      height={200}
    >
      <div className="empty" style={{ height: "100%", display: "grid", placeItems: "center" }}>
        <div>
          <div className="empty-mark">⏳</div>
          <h2>No Mosca data yet</h2>
          <p>Complete the assessment context (X, Y, Z) for your systems. Each artefact's context can be set in the Explorer.</p>
        </div>
      </div>
    </ChartShell>
  );
}
