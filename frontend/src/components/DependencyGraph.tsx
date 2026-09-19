import { useEffect, useRef, useState } from "react";
import type { DependencyGraph as DependencyGraphData, GraphNode } from "../api/client";
import { ChartShell } from "./ChartShell";
import { RiskBadge } from "./RiskBadge";
import { riskBand } from "../risk";

/** Risk band → Cytoscape node background colour */
const BAND_COLOUR: Record<string, string> = {
  p0: "#3d1a1a",
  p1: "#3d2a0a",
  p2: "#0a2d2b",
  none: "#1c2128",
};
const BAND_BORDER: Record<string, string> = {
  p0: "#ff7b7b",
  p1: "#ffb347",
  p2: "#4ecdc4",
  none: "#8b949e",
};
const NODE_SHAPE: Record<string, string> = {
  application: "rectangle",
  library: "hexagon",
  algorithm: "ellipse",
  certificate: "diamond",
  key: "tag",
};

interface DependencyGraphProps {
  data: DependencyGraphData;
  loading?: boolean;
}

/**
 * 10.3 — Crypto dependency graph (Cytoscape.js).
 * Renders application → library → algorithm as a DAG with dagre layout.
 * Node colour = risk band. Click a node to open a side panel.
 * "Blast radius" mode highlights all downstream nodes from a selected library.
 */
export function DependencyGraph({ data, loading = false }: DependencyGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<unknown>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [blastMode, setBlastMode] = useState(false);

  useEffect(() => {
    if (loading || !containerRef.current || !data.nodes.length) return;

    let cy: unknown;
    let destroyed = false;

    (async () => {
      const [{ default: Cytoscape }, { default: dagre }, { default: cytoscapeDagre }] = await Promise.all([
        import("cytoscape"),
        import("dagre"),
        import("cytoscape-dagre"),
      ]);

      if (destroyed) return;

      // Register dagre layout extension
      try {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-explicit-any
        (Cytoscape as any).use(cytoscapeDagre, dagre);
      } catch {
        // Already registered
      }

      const elements = [
        ...data.nodes.map((n) => {
          const band = riskBand(n.priority);
          return {
            data: { id: n.id, label: n.label, type: n.type, priority: n.priority, band },
            style: {
              "background-color": BAND_COLOUR[band],
              "border-color": BAND_BORDER[band],
              "border-width": 2,
              "shape": NODE_SHAPE[n.type] ?? "ellipse",
              "label": n.label.length > 22 ? n.label.slice(0, 20) + "…" : n.label,
              "color": "#e6edf3",
              "font-size": 11,
              "text-valign": "center",
              "text-wrap": "wrap",
              "width": n.type === "application" ? 120 : 90,
              "height": n.type === "application" ? 40 : 32,
            },
          };
        }),
        ...data.edges.map((e) => ({
          data: { source: e.source, target: e.target, label: e.label },
          style: {
            "line-color": "#30363d",
            "target-arrow-color": "#30363d",
            "target-arrow-shape": "vee",
            "curve-style": "bezier",
            "label": e.label ?? "",
            "font-size": 9,
            "color": "#8b949e",
            "text-rotation": "autorotate",
          },
        })),
      ];

      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-explicit-any
      cy = new (Cytoscape as any)({
        container: containerRef.current,
        elements,
        layout: {
          name: "dagre",
          rankDir: "LR",
          nodeSep: 40,
          rankSep: 120,
          animate: true,
          animationDuration: 300,
        } as object,
        style: [
          { selector: "node", style: { "font-family": "Inter, sans-serif" } },
          { selector: "edge", style: { "width": 1 } },
          { selector: "node:selected", style: { "border-width": 3, "border-color": "#4f8ef7" } },
        ],
        minZoom: 0.3,
        maxZoom: 3,
      });
      cyRef.current = cy;

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (cy as any).on("tap", "node", (event: any) => {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        const nodeId: string = event.target.data("id");
        const node = data.nodes.find((n) => n.id === nodeId) ?? null;
        setSelected(node);
      });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (cy as any).on("tap", (event: any) => {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        if (event.target === cy) setSelected(null);
      });
    })().catch(console.error);

    return () => {
      destroyed = true;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if (cy) (cy as any).destroy();
    };
  }, [data, loading]);

  /** Blast radius — highlight downstream nodes from selected */
  const handleBlastRadius = () => {
    if (!cyRef.current || !selected) return;
    setBlastMode(true);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const cy = cyRef.current as any;
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    const node = cy.$(`#${selected.id}`);
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    const downstream = node.successors();
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    cy.elements().style({ opacity: 0.15 });
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    node.style({ opacity: 1 });
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    downstream.style({ opacity: 1 });
  };

  const clearBlast = () => {
    setBlastMode(false);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    if (cyRef.current) (cyRef.current as any).elements().style({ opacity: 1 });
  };

  const dataTable = (
    <table>
      <thead><tr><th>Node</th><th>Type</th><th>Risk</th></tr></thead>
      <tbody>
        {data.nodes.map((n) => (
          <tr key={n.id}>
            <td>{n.label}</td>
            <td>{n.type}</td>
            <td>{n.priority ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );

  return (
    <ChartShell
      title="Crypto Dependency Graph"
      explainer={
        <div>
          <p><strong>How to read this graph:</strong></p>
          <p>Nodes flow left-to-right: <strong>Applications</strong> (rectangles) depend on <strong>Libraries / Protocols</strong> (hexagons) which use <strong>Algorithms</strong> (circles).</p>
          <p>Node colour = risk band (red = critical, amber = high, teal = moderate). Click a node to inspect it. Select a library, then click "Blast radius" to see everything it affects.</p>
          <p>Scroll or pinch to zoom. Click and drag to pan.</p>
        </div>
      }
      note="Click a node to inspect. Select a library → Blast radius to see what it affects."
      dataTable={dataTable}
      action={
        selected && (
          <button className="quiet" onClick={blastMode ? clearBlast : handleBlastRadius}>
            {blastMode ? "Clear blast radius" : "Blast radius ↗"}
          </button>
        )
      }
      loading={loading}
      height={480}
    >
      <div style={{ display: "flex", height: "100%", gap: "var(--space-4)" }}>
        <div ref={containerRef} className="graph-container" style={{ flex: 1 }} />
        {selected && (
          <aside className="graph-sidebar">
            <p className="eyebrow">NODE DETAIL</p>
            <h3>{selected.label}</h3>
            <RiskBadge priority={selected.priority} />
            <dl className="factors" style={{ marginTop: "var(--space-4)" }}>
              <dt>Type</dt><dd>{selected.type}</dd>
              {selected.artefact_count != null && <><dt>Artefacts</dt><dd>{selected.artefact_count}</dd></>}
            </dl>
            <a
              href={`/explorer?q=${encodeURIComponent(selected.label)}`}
              className="primary"
              style={{ display: "block", marginTop: "var(--space-4)", textAlign: "center" }}
            >
              Open in Explorer →
            </a>
          </aside>
        )}
      </div>
    </ChartShell>
  );
}
