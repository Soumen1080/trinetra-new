import { Fragment, useEffect } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { Page, Panel, Empty, Skeleton, ErrorState, ArtefactTable, ExportMenu } from "../components";
import { titleCase, formatDate } from "../risk";

/**
 * Scan detail page — live progress + partial results (§9.5b–§9.5f).
 * Primary persona: Analyst monitoring an in-flight scan.
 *
 * §4.5a — real percentage + current stage
 * §4.5b — partial results stream into the table during the scan
 * §4.5c — skeleton loader while scan data is loading
 * §4.5d — progress bar updates every 2.5 s
 * §4.5e — scan errors state cause + fix
 * §4.6d — coverage-gap banner when partial coverage
 * §9.5d — collapsible live log, hidden by default
 * §9.5e — scan history + diff against previous
 */
export function ScanDetailPage() {
  const { scanId = "" } = useParams();
  const api = useApi();
  const { token, project } = useAuth();
  const projectId = project?.id;
  const client = useQueryClient();

  const scan = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.scan(scanId),
    enabled: !!scanId && !!project,
    refetchInterval: (query) =>
      ["queued", "running"].includes(query.state.data?.status ?? "") ? 3_000 : false,
  });

  const progress = useQuery({
    queryKey: ["progress", scanId],
    queryFn: () => api.progress(scanId),
    enabled: !!scanId && !!project && ["queued", "running"].includes(scan.data?.status ?? ""),
    refetchInterval: 2_500,
  });

  const findings = useQuery({
    queryKey: ["scan-artefacts", scanId],
    queryFn: () => api.scanArtefacts(scanId, { limit: 100 }),
    enabled: !!scanId && !!project,
    refetchInterval: scan.data?.status === "running" ? 3_000 : false,
  });

  const history = useQuery({
    queryKey: ["scans", projectId, "history"],
    queryFn: () => api.scans(0, 100),
    enabled: !!project,
  });

  // §8.5 — WebSocket for live updates (falls back to polling if the connection drops)
  useEffect(() => {
    if (!token || !projectId || !scanId || !["queued", "running"].includes(scan.data?.status ?? ""))
      return;
    const protocol = location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(
      `${protocol}://${location.host}/ws/scans/${scanId}?access_token=${encodeURIComponent(token)}&project_id=${encodeURIComponent(projectId)}`,
    );
    socket.onmessage = () => {
      void client.invalidateQueries({ queryKey: ["progress", scanId] });
      void client.invalidateQueries({ queryKey: ["scan-artefacts", scanId] });
    };
    return () => socket.close();
  }, [client, projectId, scan.data?.status, scanId, token]);

  const cancel = useMutation({
    mutationFn: () => api.cancelScan(scanId),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["scan", scanId] }),
  });

  if (scan.isPending)
    return (
      <Page title="Scan" subtitle="Loading target and progress.">
        <Skeleton rows={7} />
      </Page>
    );

  if (scan.isError || !scan.data)
    return (
      <Page title="Scan" subtitle="Loading target and progress.">
        <ErrorState error={scan.error} retry={() => void scan.refetch()} />
      </Page>
    );

  const current = scan.data;
  const percent = progress.data?.percent ?? (current.status === "succeeded" ? 100 : 0);
  const previous = history.data?.items.find(
    (item) => item.id !== current.id && item.target_identifier === current.target_identifier,
  );
  const isActive = ["queued", "running"].includes(current.status);

  return (
    <Page
      title={current.display_name || current.target_identifier}
      subtitle={`${titleCase(current.target_kind)} · started ${formatDate(current.started_at || current.created_at)}`}
      breadcrumbs={[{ label: "Scans", href: "/scans" }, { label: current.display_name || current.target_identifier }]}
      action={
        <div className="page-actions">
          <ExportMenu scanId={current.id} />
          {isActive && (
            <button onClick={() => cancel.mutate()} disabled={cancel.isPending}>
              Cancel scan
            </button>
          )}
        </div>
      }
    >
      {/* §9.5b — live progress card */}
      <section className="progress-card">
        <div className="progress-header">
          <span className={`status status-${current.status}`}>{titleCase(current.status)}</span>
          <b className="progress-pct">{Math.round(percent)}%</b>
        </div>
        <div className="progress" role="progressbar" aria-valuenow={Math.round(percent)} aria-valuemin={0} aria-valuemax={100}>
          <i style={{ width: `${percent}%` }} className={isActive ? "progress-active" : ""} />
        </div>
        <p className="progress-message">
          {progress.data?.message ||
            (current.status === "running"
              ? "Receiving durable progress updates. Polling remains active if the live connection drops."
              : `Scan ${titleCase(current.status)}.`)}
        </p>

        {/* §9.5d — collapsible live log, hidden by default */}
        {progress.data && (
          <details className="live-log">
            <summary>Live scan details</summary>
            <dl>
              <dt>Current stage</dt>
              <dd>{titleCase(progress.data.stage)}</dd>
              {Object.entries(progress.data.counts).map(([name, count]) => (
                <Fragment key={name}>
                  <dt>{titleCase(name)}</dt>
                  <dd>{count.toLocaleString()}</dd>
                </Fragment>
              ))}
            </dl>
          </details>
        )}
      </section>

      {/* §9.5f — actionable error states */}
      {(current.errors?.length ?? 0) > 0 && (
        <section className="scan-errors" role="alert">
          <h2>
            {current.status === "failed"
              ? "The scan could not finish"
              : "Coverage needs review"}
          </h2>
          {current.errors?.map((error, index) => (
            <p key={index}>
              {String(error.message || error.code || "The scanner reported an issue.")}{" "}
              <small>
                Check the target address and scanner availability, then rescan.
              </small>
            </p>
          ))}
        </section>
      )}

      {/* §4.6d / §9.6g — coverage-gap banner */}
      {current.status === "partial" && (
        <section className="coverage-banner" role="status">
          ⚠ This scan completed with partial coverage. Some artefacts may be missing. Review the
          scan errors above before treating this inventory as complete.
        </section>
      )}

      {/* §9.5e — diff against previous scan */}
      {previous && (
        <Panel
          title="Change from the previous scan"
          note={`Compared with ${formatDate(previous.created_at)} on the same target.`}
        >
          <p className="diff">
            <b>
              {current.artefact_count - previous.artefact_count > 0 ? "+" : ""}
              {current.artefact_count - previous.artefact_count}
            </b>{" "}
            artefacts since the previous scan ({previous.artefact_count} → {current.artefact_count}
            ).
          </p>
        </Panel>
      )}

      {/* §9.5c — partial results stream into the table */}
      <Panel
        title="Results"
        note={
          findings.data?.partial_results
            ? "Partial results — new findings appear as the scan continues."
            : "Results ordered by priority."
        }
      >
        {findings.isPending ? (
          <Skeleton rows={5} />
        ) : findings.isError ? (
          <ErrorState error={findings.error} retry={() => void findings.refetch()} />
        ) : findings.data?.items.length ? (
          <ArtefactTable rows={findings.data.items} />
        ) : (
          <Empty title="No findings yet" icon="🔍">
            The scanner has not emitted crypto artefacts for this target yet.
          </Empty>
        )}
      </Panel>
    </Page>
  );
}
