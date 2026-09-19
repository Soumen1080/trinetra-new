import { useNavigate } from "react-router-dom";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  Cell, LabelList, ResponsiveContainer,
} from "recharts";
import type { AlgorithmBucket } from "../api/client";
import { ChartShell } from "./ChartShell";

const SAFE_LABEL = "✅ Quantum-safe";
const VULN_LABEL = "⚠ Quantum-vulnerable";

interface AlgorithmInventoryProps {
  data: AlgorithmBucket[];
  loading?: boolean;
}

/**
 * 10.6 — Algorithm inventory view.
 * Horizontal bar chart: one bar per (algorithm, key-size) combination.
 * Vulnerable ones shown in red, quantum-safe in teal.
 * Click a bar → filters Explorer to that algorithm.
 */
export function AlgorithmInventory({ data, loading = false }: AlgorithmInventoryProps) {
  const navigate = useNavigate();

  const chartData = data
    .map((bucket) => ({
      name: bucket.key_size
        ? `${bucket.algorithm} ${bucket.key_size}`
        : bucket.algorithm,
      algorithm: bucket.algorithm,
      mode: bucket.mode,
      count: bucket.count,
      safe: bucket.quantum_safe,
    }))
    .sort((a, b) => {
      // Vulnerable first, then by count descending
      if (a.safe !== b.safe) return a.safe ? 1 : -1;
      return b.count - a.count;
    });

  const handleClick = (entry: { algorithm: string }) => {
    navigate(`/explorer?algorithm=${encodeURIComponent(entry.algorithm)}`);
  };

  const dataTable = (
    <table>
      <thead>
        <tr>
          <th>Algorithm</th>
          <th>Mode</th>
          <th>Count</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {data.map((bucket, index) => (
          <tr key={index}>
            <td>{bucket.algorithm}</td>
            <td>{bucket.mode ?? "—"}</td>
            <td>{bucket.count}</td>
            <td>{bucket.quantum_safe ? SAFE_LABEL : VULN_LABEL}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );

  return (
    <ChartShell
      title="Algorithm Inventory"
      explainer={
        <div>
          <p><strong>How to read this chart:</strong></p>
          <p>Each bar is one algorithm (or algorithm + key-size combination). Bar length = how many times it appears across the project.</p>
          <p><span style={{ color: "var(--p0)" }}>Red bars</span> are quantum-vulnerable: RSA, ECDSA, ECDH, DH, DSA — all broken by Shor's algorithm on a CRQC.</p>
          <p><span style={{ color: "var(--p2)" }}>Teal bars</span> are quantum-safe: AES-256, ML-KEM, ML-DSA, SLH-DSA, SHAKE, SHA-3.</p>
          <p>Click any bar to open the Explorer filtered to that algorithm.</p>
        </div>
      }
      note="Red = quantum-vulnerable, teal = safe. Click a bar to filter the Explorer."
      dataTable={dataTable}
      loading={loading}
      height={Math.max(280, chartData.length * 38 + 60)}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={chartData}
          layout="vertical"
          margin={{ top: 0, right: 60, left: 0, bottom: 0 }}
          onClick={(payload: unknown) => {
            const p = payload as { activePayload?: Array<{ payload?: { algorithm?: string } }> };
            if (p?.activePayload?.[0]?.payload?.algorithm) {
              handleClick({ algorithm: p.activePayload[0].payload.algorithm });
            }
          }}
          style={{ cursor: "pointer" }}
        >
          <CartesianGrid horizontal={false} strokeDasharray="3 3" stroke="var(--line)" />
          <XAxis type="number" tick={{ fill: "var(--muted)", fontSize: 11 }} />
          <YAxis
            type="category"
            dataKey="name"
            width={140}
            tick={{ fill: "var(--text-2)", fontSize: 11 }}
          />
          <Tooltip
            contentStyle={{ background: "var(--surface)", border: "1px solid var(--line)", borderRadius: "6px" }}
            formatter={(value: unknown, _name: unknown, props: unknown) => {
              const p = props as { payload?: { safe?: boolean } };
              return [
                `${String(value ?? 0)} artefacts`,
                p?.payload?.safe ? SAFE_LABEL : VULN_LABEL,
              ];
            }}
          />
          <Bar dataKey="count" name="Occurrences" radius={[0, 4, 4, 0]}>
            <LabelList
              dataKey="count"
              position="right"
              style={{ fill: "var(--muted)", fontSize: 11 }}
            />
            {chartData.map((entry, index) => (
              <Cell
                key={index}
                fill={entry.safe ? "var(--p2)" : "var(--p0)"}
                fillOpacity={0.85}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartShell>
  );
}
