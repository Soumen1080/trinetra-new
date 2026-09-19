import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import {
  Page,
  Panel,
  Empty,
  Skeleton,
  ErrorState,
  RiskBadge,
  Tooltip,
} from "../components";
import { riskBand, riskCopy, titleCase } from "../risk";
import { problem } from "../components/ErrorState";
import type { Assessment } from "../api/client";

/**
 * Full artefact detail page — evidence, risk factors, Mosca timing,
 * what-if scenario, and recommendation (§9.6e expanded view).
 * Primary persona: Developer / app owner — "What is wrong and what do I change?"
 */
export function ArtefactPage() {
  const { artefactId = "" } = useParams();
  const api = useApi();
  const { project, user } = useAuth();
  const [scenario, setScenario] = useState("baseline");
  const [years, setYears] = useState("10");

  const detail = useQuery({
    queryKey: ["artefact", artefactId],
    queryFn: () => api.artefact(artefactId),
    enabled: !!artefactId && !!project,
  });
  const risk = useQuery({
    queryKey: ["risk", artefactId],
    queryFn: () => api.risk(artefactId),
    enabled: !!artefactId && !!project,
  });
  const mosca = useQuery({
    queryKey: ["mosca", artefactId],
    queryFn: () => api.mosca(artefactId),
    enabled: !!artefactId && !!project,
  });
  const whatIf = useMutation({
    mutationFn: () => api.whatIf(artefactId, { x_years: Number(years), scenario }),
  });

  if (detail.isPending)
    return (
      <Page title="Artefact detail" subtitle="Loading evidence and assessment.">
        <Skeleton rows={12} />
      </Page>
    );

  if (detail.isError || !detail.data)
    return (
      <Page title="Artefact detail" subtitle="Loading evidence and assessment.">
        <ErrorState error={detail.error} retry={() => void detail.refetch()} />
      </Page>
    );

  const data = detail.data;
  const item = data.artefact;
  const verdict = risk.data?.assessment;
  const m = mosca.data?.mosca;
  const band = riskBand(item.priority);

  return (
    <Page
      title={item.name}
      subtitle={`${titleCase(item.type)} · ${item.location || "location unavailable"}`}
      breadcrumbs={[
        { label: "Explorer", href: "/explorer" },
        { label: item.name },
      ]}
      action={<Link to="/explorer">← Back to Explorer</Link>}
    >
      {/* §4.3b — plain-English summary banner */}
      <section className="detail-banner">
        <RiskBadge priority={item.priority} />
        <div>
          <b>{item.recommendation || riskCopy[band].action}</b>
          <p>
            {item.risk_score == null
              ? "No misleading score is shown: complete the context to calculate an assessment."
              : `Risk score ${item.risk_score.toFixed(1)} / 100`}
          </p>
        </div>
      </section>

      <section className="detail-grid">
        {/* §4.6a — evidence at file:line */}
        <Panel title="Evidence" note="Every finding points to the source material that supports it.">
          <EvidenceSection items={data.evidence} fallback={item.location} />
        </Panel>

        {/* §4.6b — risk factors, not a black box */}
        <Panel title="Risk factors" note="Inputs are visible — this is not a black box.">
          {risk.isPending ? (
            <Skeleton rows={4} />
          ) : verdict ? (
            <FactorList assessment={verdict} />
          ) : (
            <Empty title="Assessment pending" icon="⏳">
              {risk.data?.message || "Run or complete the assessment context."}
            </Empty>
          )}
        </Panel>

        {/* §4.6c — Mosca X/Y/Z with arithmetic */}
        <Panel
          title="Mosca timing"
          note="The migration deadline, shown with its arithmetic."
        >
          <div className="mosca">
            {m ? (
              <>
                <MoscaCell
                  label="X — data life"
                  value={m.x_years}
                  unit="yr"
                  tooltip="How long recorded data must stay secret (confidentiality life)."
                />
                <MoscaCell
                  label="Y — quantum break"
                  value={m.y_years}
                  unit="yr"
                  tooltip="Scenario-based estimate of when a CRQC could break this algorithm."
                />
                <MoscaCell
                  label="Z — migration"
                  value={m.z_years}
                  unit="yr"
                  tooltip="Estimated migration duration: inventory + design + rollout + verification."
                />
                <div className="mosca-deadline">
                  <span>
                    Migration deadline{" "}
                    <Tooltip label="How the deadline is calculated" glossaryTerm="Mosca timing">
                      Deadline = Y − Z. If X &gt; Y − Z, migration is overdue under this scenario.
                    </Tooltip>
                  </span>
                  <b>{m.migration_deadline_year ?? "Needs context"}</b>
                </div>
              </>
            ) : (
              <Empty title="Timing unavailable" icon="⏳">
                {mosca.data?.message || "Assessment inputs are still missing."}
              </Empty>
            )}
          </div>
        </Panel>

        {/* What-if scenario */}
        <Panel
          title="What-if scenario"
          note="A temporary calculation — it never overwrites the stored assessment."
        >
          <div className="what-if">
            <label>
              Confidentiality life (years){" "}
              <Tooltip label="What confidentiality life means" glossaryTerm="Mosca timing">
                X in Mosca: how long data protected by this algorithm must remain secret.
              </Tooltip>
              <input
                type="number"
                min="0"
                max="100"
                value={years}
                onChange={(event) => setYears(event.target.value)}
              />
            </label>
            <label>
              Quantum scenario
              <select value={scenario} onChange={(event) => setScenario(event.target.value)}>
                <option value="optimistic">Optimistic (2040+)</option>
                <option value="baseline">Baseline (2035)</option>
                <option value="pessimistic">Pessimistic (2030)</option>
              </select>
            </label>
            <button
              onClick={() => whatIf.mutate()}
              disabled={whatIf.isPending || user?.role === "viewer"}
            >
              {whatIf.isPending ? "Calculating…" : "Compare scenario"}
            </button>
            {whatIf.data && (
              <div className="whatif-result">
                <RiskBadge priority={whatIf.data.assessment.priority as string} />
                <span>New score: {String(whatIf.data.assessment.final_score ?? "not available")}</span>
              </div>
            )}
            {whatIf.error && <p className="form-error">{problem(whatIf.error)}</p>}
          </div>
        </Panel>
      </section>

      {/* §4.4a — recommendation panel */}
      <Panel
        title="Recommendation"
        note="A recommended action is tied to the finding and current policy."
      >
        {data.recommendations.length ? (
          <ul className="recommendations">
            {data.recommendations.map((rec, index) => (
              <li key={index}>
                {String(rec.title || rec.recommendation || JSON.stringify(rec))}
              </li>
            ))}
          </ul>
        ) : (
          <Empty title="No recommendation generated" icon="💡">
            Add context or rerun the assessment to create an actionable recommendation.
          </Empty>
        )}
      </Panel>
    </Page>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function MoscaCell({
  label,
  value,
  unit,
  tooltip,
}: {
  label: string;
  value?: number | null;
  unit: string;
  tooltip: string;
}) {
  return (
    <div>
      <span>
        {label}{" "}
        <Tooltip label={label}>{tooltip}</Tooltip>
      </span>
      <b>
        {value != null ? `${value} ${unit}` : "Unknown"}
      </b>
    </div>
  );
}

function EvidenceSection({
  items,
  fallback,
}: {
  items: Array<Record<string, unknown>>;
  fallback?: string | null;
}) {
  if (!items.length)
    return (
      <p className="muted">
        {fallback
          ? `Detected at ${fallback}. The scanner did not supply a finer-grained reference.`
          : "No evidence pointer was supplied."}
      </p>
    );
  return (
    <ul className="evidence">
      {items.map((item, index) => (
        <li key={index}>
          <b>{String(item.file || item.path || item.location || "Evidence")}</b>
          <small>
            {item.line ? `Line ${item.line}` : "Exact position not supplied"} ·{" "}
            {String(item.confidence || "confidence not supplied")}
          </small>
          {typeof item.snippet === "string" && item.snippet && (
            <pre className="code-evidence">
              <code>{item.snippet}</code>
            </pre>
          )}
        </li>
      ))}
    </ul>
  );
}

function FactorList({ assessment }: { assessment: Assessment }) {
  const factors = (assessment.factors ?? assessment.factor_breakdown ?? {}) as Record<
    string,
    unknown
  >;
  const entries = Object.entries(factors).filter(([, v]) => typeof v !== "object");
  return entries.length ? (
    <dl className="factors">
      {entries.map(([name, value]) => (
        <>
          <dt key={`${name}-t`}>{titleCase(name)}</dt>
          <dd key={`${name}-d`}>{String(value ?? "Unknown")}</dd>
        </>
      ))}
    </dl>
  ) : (
    <p className="muted">No factor breakdown was returned for this assessment.</p>
  );
}
