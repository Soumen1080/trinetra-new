import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { useApi } from "../hooks/useApi";
import { riskBand, riskCopy, titleCase } from "../risk";
import { RiskBadge } from "./RiskBadge";
import { Skeleton } from "./Skeleton";
import { ErrorState } from "./ErrorState";

interface ArtefactDrawerProps {
  artefactId: string;
  close: () => void;
}

/**
 * Artefact detail drawer (§4.6 — the trust-builder):
 * 1. Plain-English summary at the top (§4.3b, §4.6)
 * 2. Syntax-highlighted code evidence at file:line (§4.6a)
 * 3. Mosca X/Y/Z with the arithmetic (§4.6c)
 * 4. Recommendation with rationale
 * 5. Confidence level + detection method (§4.6b)
 * 6. Primary action button (§4.4a)
 */
export function ArtefactDrawer({ artefactId, close }: ArtefactDrawerProps) {
  const api = useApi();
  const detail = useQuery({
    queryKey: ["artefact-drawer", artefactId],
    queryFn: () => api.artefact(artefactId),
  });
  const risk = useQuery({
    queryKey: ["risk-drawer", artefactId],
    queryFn: () => api.risk(artefactId),
  });

  // Close drawer on Escape
  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "Escape") close();
  };

  if (detail.isPending)
    return (
      <aside className="drawer" role="dialog" aria-modal="true" aria-label="Artefact detail" onKeyDown={handleKeyDown}>
        <Skeleton rows={8} />
      </aside>
    );

  if (detail.isError || !detail.data)
    return (
      <aside className="drawer" role="dialog" aria-modal="true" aria-label="Artefact detail" onKeyDown={handleKeyDown}>
        <button className="icon-button drawer-close" onClick={close} aria-label="Close detail">
          ×
        </button>
        <ErrorState error={detail.error} retry={() => void detail.refetch()} />
      </aside>
    );

  const item = detail.data.artefact;
  const evidence = detail.data.evidence[0];
  const snippet = evidence && typeof evidence.snippet === "string" ? evidence.snippet : undefined;
  const band = riskBand(item.priority);
  const mosca = risk.data?.assessment?.mosca;

  /** §4.3b — one plain-English summary before any jargon. */
  const plainSummary = buildPlainSummary(item);

  return (
    <aside className="drawer" role="dialog" aria-modal="true" aria-label={`${item.name} detail`} onKeyDown={handleKeyDown}>
      <header>
        <div>
          <p className="eyebrow">ARTEFACT DETAIL</p>
          <h2>{item.name}</h2>
        </div>
        <button className="icon-button drawer-close" onClick={close} aria-label="Close detail">
          ×
        </button>
      </header>

      <RiskBadge priority={item.priority} />

      {/* §4.3b — plain-English summary FIRST, before any technical detail */}
      <p className="drawer-summary">{plainSummary}</p>

      {/* §4.6b — confidence and detection method, openly shown */}
      <dl className="factors">
        <dt>Detected by</dt>
        <dd>{titleCase(item.discovered_by)}</dd>
        <dt>Confidence</dt>
        <dd>{String(evidence?.confidence || "Not supplied")}</dd>
        <dt>Risk score</dt>
        <dd>
          {item.risk_score == null
            ? "Needs context"
            : `${item.risk_score.toFixed(1)} / 100`}
        </dd>
      </dl>

      {/* §4.6a — evidence at file:line */}
      <h3>Evidence</h3>
      <EvidenceList items={detail.data.evidence} fallback={item.location} />
      {snippet && (
        <pre className="code-evidence">
          <code>{snippet}</code>
        </pre>
      )}

      {/* §4.6c — Mosca X/Y/Z with arithmetic */}
      {mosca && (
        <>
          <h3>Mosca timing</h3>
          <div className="mosca-mini">
            <div>
              <span>X — data life</span>
              <b>{mosca.x_years ?? "Unknown"} yr</b>
            </div>
            <div>
              <span>Y — quantum break</span>
              <b>{mosca.y_years ?? "Unknown"} yr</b>
            </div>
            <div>
              <span>Z — migration</span>
              <b>{mosca.z_years ?? "Unknown"} yr</b>
            </div>
            <div className={`mosca-verdict ${mosca.migration_deadline_year ? "deadline" : ""}`}>
              <span>Deadline (Y − Z)</span>
              <b>{mosca.migration_deadline_year ?? "Needs context"}</b>
            </div>
          </div>
        </>
      )}

      {/* §4.4a — clear primary action */}
      <Link className="primary drawer-action" to={`/artefacts/${item.id}`}>
        Open full assessment →
      </Link>
    </aside>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function buildPlainSummary(item: { algorithm?: string | null; type?: string | null; location?: string | null; recommendation?: string | null; priority?: string | null }): string {
  const algo = item.algorithm || `This ${titleCase(item.type ?? "crypto asset").toLowerCase()}`;
  const loc = item.location ? `at ${item.location}` : "in your codebase";
  const band = riskBand(item.priority);
  const action = riskCopy[band].action;
  const rec = item.recommendation ? ` ${item.recommendation}.` : "";
  return `${algo} was found ${loc}. ${action}.${rec}`;
}

function EvidenceList({
  items,
  fallback,
}: {
  items: Array<Record<string, unknown>>;
  fallback?: string | null;
}) {
  if (!items.length) {
    return (
      <p className="muted">
        {fallback
          ? `Detected at ${fallback}. The scanner did not supply a finer-grained evidence reference.`
          : "No evidence pointer was supplied."}
      </p>
    );
  }
  return (
    <ul className="evidence">
      {items.map((item, index) => (
        <li key={index}>
          <b>{String(item.file || item.path || item.location || "Evidence")}</b>
          <small>
            {item.line ? `Line ${item.line}` : "Exact position not supplied"} ·{" "}
            {String(item.confidence || "confidence not supplied")}
          </small>
        </li>
      ))}
    </ul>
  );
}
