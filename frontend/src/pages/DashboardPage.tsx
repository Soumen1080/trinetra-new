import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { Page, Panel, Empty, Skeleton, ErrorState, RiskBadge, Tooltip, ArtefactTable, DemoDataLoader } from "../components";
import { titleCase, formatDate, riskBand } from "../risk";

/**
 * Dashboard — the executive screen (§4.1, §9.4).
 * Primary persona: Executive / CISO — "How exposed are we, and what will it cost?"
 * Must be readable with zero clicks and no training (§9.4g).
 */
export function DashboardPage() {
  const api = useApi();
  const { project } = useAuth();

  const dashboard = useQuery({
    queryKey: ["dashboard", project?.id],
    queryFn: api.dashboard,
    enabled: !!project,
  });
  const scans = useQuery({
    queryKey: ["scans", project?.id, "recent"],
    queryFn: () => api.scans(0, 8),
    enabled: !!project,
  });

  if (!project)
    return (
      <Page
        title="Readiness overview"
        subtitle="The current quantum risk picture, with evidence behind every number."
      >
        <Empty
          title="Choose a project"
          icon="📂"
          action={<p className="muted">Select a project from the sidebar to see scoped risk data.</p>}
        >
          You need a project before Trinetra can show scoped risk data.
        </Empty>
      </Page>
    );

  if (dashboard.isPending)
    return (
      <Page title="Readiness overview" subtitle="Loading the current risk picture…">
        <Skeleton rows={9} />
      </Page>
    );

  if (dashboard.isError)
    return (
      <Page title="Readiness overview" subtitle="Could not load dashboard data.">
        <ErrorState error={dashboard.error} retry={() => void dashboard.refetch()} />
      </Page>
    );

  const data = dashboard.data;
  const topApplications = data.top_applications ?? [];
  const artefactTypes = data.artefact_type_counts ?? {};
  const trend = data.trend ?? [];

  /** §9.4a — at most 5 headline tiles (§4.2b). */
  const tiles: Array<[ReactNode, string | number, string]> = [
    [
      <>
        Total artefacts{" "}
        <Tooltip label="What total artefacts means" glossaryTerm="CBOM">
          Every cryptographic artefact found across this project's retained scans.
        </Tooltip>
      </>,
      data.total_artefacts.toLocaleString(),
      "Inventory scope",
    ],
    [
      <>
        Quantum-vulnerable{" "}
        <Tooltip label="What quantum-vulnerable means" glossaryTerm="Quantum vulnerable">
          Algorithms affected by Shor's or Grover's quantum advantage. These need a PQC migration plan.
        </Tooltip>
      </>,
      data.quantum_vulnerable_count.toLocaleString(),
      "Needs migration planning",
    ],
    [
      <>
        Critical risks{" "}
        <Tooltip label="What critical risks means" glossaryTerm="Priority">
          P0 findings — current policy says act now, before a CRQC arrives.
        </Tooltip>
      </>,
      (data.priority_counts.p0 ?? 0).toLocaleString(),
      "Act this quarter",
    ],
    [
      <>
        Quantum-safe{" "}
        <Tooltip label="What quantum-safe means" glossaryTerm="Quantum vulnerable">
          Percentage explicitly classified as quantum-safe. Unknowns are never counted safe (P3).
        </Tooltip>
      </>,
      data.quantum_safe_percent == null
        ? "Not measured"
        : `${data.quantum_safe_percent.toFixed(0)}%`,
      "Explicitly classified",
    ],
    [
      <>
        Nearest Mosca deadline{" "}
        <Tooltip label="What the Mosca deadline means" glossaryTerm="Mosca timing">
          Earliest assessed migration deadline (Y − Z) across all systems in this project.
        </Tooltip>
      </>,
      data.nearest_mosca_deadline_year ?? "Needs context",
      "Earliest migration date",
    ],
  ];

  return (
    <Page
      title="Readiness overview"
      subtitle="The current quantum risk picture. Every number links to its evidence."
      action={
        <Link className="primary" to="/scans" id="dashboard-launch-scan">
          Launch a scan
        </Link>
      }
    >
      {/* §9.4a — 5 headline metric tiles */}
      <section className="metric-grid" aria-label="Headline metrics">
        {tiles.map(([label, value, hint], index) => (
          <article className="metric" key={index}>
            <span className="metric-label">{label}</span>
            <strong className="metric-value">{value}</strong>
            <small className="metric-hint">{hint}</small>
          </article>
        ))}
      </section>

      <section className="two-column">
        <Panel
          title="Priority distribution"
          note="A risk band always pairs with a recommended next action."
        >
          <RiskDonut counts={data.priority_counts} />
        </Panel>
        <Panel
          title="Artefact types"
          note="Click a type to explore that category in the CBOM Explorer."
        >
          <TypeBreakdown counts={artefactTypes} />
        </Panel>
      </section>

      <section className="two-column">
        {/* §9.4b — Top 5 things to fix this quarter (§4.4c) */}
        <Panel
          title="Top 5 things to fix this quarter"
          note="Highest-priority findings — one click from the evidence."
        >
          {data.worst_offenders?.length ? (
            <ArtefactTable rows={data.worst_offenders.slice(0, 5)} compact />
          ) : (
            <Empty title="No critical findings" icon="✅">
              No P0 artefacts in this project. Run a scan to populate the inventory.
            </Empty>
          )}
        </Panel>

        {/* §9.4d — Top at-risk applications */}
        <Panel
          title="Top at-risk applications"
          note="Applications with the most critical or high-risk findings."
        >
          {topApplications.length ? (
            <ul className="app-list">
              {topApplications.map((app) => (
                <li key={app.id ?? app.name}>
                  <Link to={`/explorer?application_id=${app.id ?? ""}`}>
                    <span>{app.name}</span>
                    <b>{app.at_risk_count}</b>
                  </Link>
                </li>
              ))}
            </ul>
          ) : (
            <Empty title="No at-risk applications" icon="📱">
              Assign findings to applications to see their migration exposure here.
            </Empty>
          )}
        </Panel>
      </section>

      {/* §9.4e — Posture trend */}
      <section className="two-column">
        <Panel title="Posture trend" note="Artefact and critical counts across recent scans.">
          <TrendChart trend={trend} />
        </Panel>
        <Panel title="Recent scan activity" note="History is retained per target.">
          {scans.isPending ? (
            <Skeleton rows={4} />
          ) : scans.data?.items.length ? (
            <ul className="timeline">
              {scans.data.items.map((scan) => (
                <li key={scan.id}>
                  <span className={`status status-${scan.status}`}>{titleCase(scan.status)}</span>
                  <div>
                    <Link to={`/scans/${scan.id}`}>{scan.display_name || scan.target_identifier}</Link>
                    <small>
                      {formatDate(scan.created_at)} · {scan.artefact_count} artefacts
                    </small>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <Empty
              title="No scans yet"
              icon="🔍"
              action={
                <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", justifyContent: "center" }}>
                  <Link className="button" to="/scans">
                    Launch a first scan
                  </Link>
                  <DemoDataLoader variant="secondary" />
                </div>
              }
            >
              A scan turns evidence into a prioritised migration view, or load the demo dataset to explore immediately.
            </Empty>
          )}
        </Panel>
      </section>
    </Page>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function RiskDonut({ counts }: { counts: Record<string, number> }) {
  const total = Math.max(1, Object.values(counts).reduce((sum, c) => sum + c, 0));
  let cursor = 0;
  const colours: Record<string, string> = {
    p0: "var(--p0)",
    p1: "var(--p1)",
    p2: "var(--p2)",
    none: "var(--none)",
  };
  const stops = (["p0", "p1", "p2", "none"] as const)
    .map((band) => {
      const end = cursor + ((counts[band] ?? 0) / total) * 100;
      const stop = `${colours[band]} ${cursor}% ${end}%`;
      cursor = end;
      return stop;
    })
    .join(", ");

  return (
    <div className="risk-distribution">
      <div
        className="risk-donut"
        style={{ background: `conic-gradient(${stops})` }}
        role="img"
        aria-label={`Risk distribution: ${counts.p0 ?? 0} critical, ${counts.p1 ?? 0} high, ${counts.p2 ?? 0} moderate, ${counts.none ?? 0} not assessed`}
      >
        <span>
          {Object.values(counts).reduce((sum, c) => sum + c, 0).toLocaleString()}
          <small>findings</small>
        </span>
      </div>
      <div className="risk-bars">
        {(["p0", "p1", "p2", "none"] as const).map((band) => (
          <Link to={`/explorer?priority=${band}`} key={band} className="risk-bar-row">
            <div>
              <RiskBadge priority={band} />
              <span>{(counts[band] ?? 0).toLocaleString()}</span>
            </div>
            <i>
              <b
                className={`bar-${band}`}
                style={{ width: `${((counts[band] ?? 0) / total) * 100}%` }}
              />
            </i>
          </Link>
        ))}
      </div>
    </div>
  );
}

function TypeBreakdown({ counts }: { counts: Record<string, number> }) {
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
  return (
    <ul className="app-list">
      {Object.entries(counts)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 7)
        .map(([type, count]) => (
          <li key={type}>
            <Link to={`/explorer?type=${type}`}>
              <span>
                <span aria-hidden="true">{TYPE_ICONS[type] ?? "⬡"} </span>
                {titleCase(type)}
              </span>
              <b>{count.toLocaleString()}</b>
            </Link>
          </li>
        ))}
    </ul>
  );
}

function TrendChart({
  trend,
}: {
  trend: Array<{ scan_id: string; created_at: string; artefact_count: number; critical_count: number }>;
}) {
  if (!trend.length)
    return (
      <Empty title="No scan history" icon="📈">
        Run another scan to start a posture trend.
      </Empty>
    );
  const max = Math.max(...trend.map((p) => p.artefact_count), 1);
  return (
    <div className="trend" aria-label="Recent scan posture trend">
      {[...trend].reverse().map((point) => (
        <Link
          to={`/scans/${point.scan_id}`}
          key={point.scan_id}
          title={`${formatDate(point.created_at)}: ${point.artefact_count} artefacts, ${point.critical_count} critical`}
        >
          <i style={{ height: `${Math.max(8, (point.artefact_count / max) * 100)}%` }} />
          <small>{point.critical_count} critical</small>
        </Link>
      ))}
    </div>
  );
}

/** Needed for the risk badge import in RiskDonut. */
const _riskBand = riskBand;
void _riskBand;
