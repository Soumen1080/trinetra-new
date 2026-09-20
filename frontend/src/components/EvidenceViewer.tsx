import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "../hooks/useApi";
import { Skeleton } from "./Skeleton";
import { ErrorState } from "./ErrorState";
import { titleCase } from "../risk";

interface EvidenceViewerProps {
  artefactId: string;
  scanId?: string;
}

// Type guard helper to safely extract string values from unknown evidence data
function getString(obj: Record<string, unknown>, key: string): string | undefined {
  const value = obj[key];
  return typeof value === "string" ? value : undefined;
}

function getNumber(obj: Record<string, unknown>, key: string): number | undefined {
  const value = obj[key];
  return typeof value === "number" ? value : undefined;
}

/**
 * Evidence viewer modal (§4.6 — show evidence and provenance chain).
 * Displays:
 * - Raw scanner output
 * - Detection method and confidence
 * - File path and line number with syntax-highlighted snippet
 * - Scanner version and timestamp
 * - Provenance chain (which scanner → which file → which line)
 */
export function EvidenceViewer({ artefactId, scanId }: EvidenceViewerProps) {
  const api = useApi();
  const [showRaw, setShowRaw] = useState(false);

  const detail = useQuery({
    queryKey: ["artefact-evidence", artefactId],
    queryFn: () => api.artefact(artefactId),
  });

  if (detail.isPending) return <Skeleton rows={5} />;
  if (detail.isError || !detail.data)
    return <ErrorState error={detail.error} retry={() => void detail.refetch()} />;

  const { artefact, evidence } = detail.data;
  const primaryEvidence = evidence[0];

  const scannerVersion = primaryEvidence ? getString(primaryEvidence, "scanner_version") : undefined;
  const confidence = primaryEvidence ? getString(primaryEvidence, "confidence") : undefined;
  const detectionMethod = primaryEvidence ? getString(primaryEvidence, "detection_method") : undefined;
  const timestamp = primaryEvidence ? getString(primaryEvidence, "timestamp") : undefined;
  const primaryFile = primaryEvidence ? getString(primaryEvidence, "file") : undefined;
  const primaryLine = primaryEvidence ? getNumber(primaryEvidence, "line") : undefined;

  return (
    <section className="evidence-viewer" aria-label="Evidence and provenance">
      <header>
        <h3>Evidence</h3>
        <p className="muted">
          Every finding links to the source evidence. Trust is built through transparency.
        </p>
      </header>

      {/* §4.6b — Detection method and confidence */}
      <dl className="evidence-metadata">
        <dt>Detected by</dt>
        <dd>
          {titleCase(artefact.discovered_by)}
          {scannerVersion && (
            <small> v{scannerVersion}</small>
          )}
        </dd>

        <dt>Confidence</dt>
        <dd>
          <ConfidenceBadge level={confidence ?? "unknown"} />
        </dd>

        <dt>Detection method</dt>
        <dd>{detectionMethod ?? "Static pattern match"}</dd>

        {timestamp && (
          <>
            <dt>Discovered</dt>
            <dd>{new Date(timestamp).toISOString()}</dd>
          </>
        )}
      </dl>

      {/* §4.6a — Source evidence at file:line */}
      {evidence.map((item, index) => {
        const file = getString(item, "file");
        const path = getString(item, "path");
        const location = getString(item, "location");
        const line = getNumber(item, "line");
        const snippet = getString(item, "snippet");
        const context = getString(item, "context");

        return (
          <div key={index} className="evidence-item">
            <h4>
              {file || path || location || "Source location"}
              {line && <span className="line-number"> : {line}</span>}
            </h4>

            {snippet && (
              <pre className="code-evidence">
                <code>{snippet}</code>
              </pre>
            )}

            {context && (
              <p className="evidence-context">
                <strong>Context:</strong> {context}
              </p>
            )}
          </div>
        );
      })}

      {/* §4.6c — Provenance chain */}
      <div className="provenance-chain">
        <h4>Provenance chain</h4>
        <ol className="provenance-steps">
          <li>
            <strong>Scanner:</strong> {titleCase(artefact.discovered_by)}
            {scanId && <small> (Scan {scanId.slice(0, 8)})</small>}
          </li>
          <li>
            <strong>Target:</strong> {artefact.location || "Unknown location"}
          </li>
          {primaryFile && (
            <li>
              <strong>Source file:</strong> {primaryFile}
              {primaryLine && ` line ${primaryLine}`}
            </li>
          )}
          <li>
            <strong>Algorithm identified:</strong> {artefact.algorithm || "Unknown"}
          </li>
        </ol>
      </div>

      {/* §4.6d — Raw scanner output (toggle) */}
      <details className="raw-output" open={showRaw}>
        <summary onClick={(e) => { e.preventDefault(); setShowRaw(!showRaw); }}>
          Raw scanner output
        </summary>
        {showRaw && (
          <pre className="raw-data">
            <code>{JSON.stringify(primaryEvidence || artefact, null, 2)}</code>
          </pre>
        )}
      </details>
    </section>
  );
}

/**
 * Confidence badge with colour + text + icon (§4.8b, §4.9b).
 */
function ConfidenceBadge({ level }: { level: string | number }) {
  const normalized = String(level).toLowerCase();
  const config: Record<string, { label: string; icon: string; className: string }> = {
    high: { label: "High", icon: "✓", className: "confidence-high" },
    medium: { label: "Medium", icon: "~", className: "confidence-medium" },
    low: { label: "Low", icon: "?", className: "confidence-low" },
    unknown: { label: "Unknown", icon: "?", className: "confidence-unknown" },
  };

  const match = config[normalized] || config.unknown;

  return (
    <span className={`confidence-badge ${match.className}`}>
      <span aria-hidden="true">{match.icon}</span> {match.label}
    </span>
  );
}
