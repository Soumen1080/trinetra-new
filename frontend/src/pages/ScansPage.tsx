import { useState } from "react";
import type { FormEvent } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { Page, Panel, Empty, Skeleton, ErrorState } from "../components";
import { titleCase, formatDate } from "../risk";
import type { Scan } from "../api/client";
import { problem } from "../components/ErrorState";

/**
 * Scans page — the scan management hub (§9.5).
 * Primary persona: Security analyst launching and monitoring scans.
 */
export function ScansPage() {
  const api = useApi();
  const { project } = useAuth();
  const client = useQueryClient();
  const [formOpen, setFormOpen] = useState(false);

  const capabilities = useQuery({
    queryKey: ["scan-capabilities"],
    queryFn: api.capabilities,
    enabled: formOpen,
  });
  const scans = useQuery({
    queryKey: ["scans", project?.id],
    queryFn: () => api.scans(),
    enabled: !!project,
  });
  const create = useMutation({
    mutationFn: api.createScan,
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["scans", project?.id] });
      setFormOpen(false);
    },
  });

  if (!project)
    return (
      <Page title="Scans" subtitle="Launch and monitor discovery across this project.">
        <Empty title="Choose a project" icon="📂">
          A scan must belong to a project.
        </Empty>
      </Page>
    );

  return (
    <Page
      title="Scans"
      subtitle="Launch a target, follow durable progress, and inspect results as they arrive."
      action={
        <button
          id="scans-launch-btn"
          className="primary"
          onClick={() => setFormOpen(true)}
        >
          + Launch scan
        </button>
      }
    >
      {formOpen && (
        <ScanForm
          capabilities={capabilities.data?.targets ?? []}
          pending={create.isPending}
          error={create.error}
          close={() => setFormOpen(false)}
          submit={(payload) => create.mutate(payload)}
        />
      )}

      {scans.isPending ? (
        <Skeleton rows={7} />
      ) : scans.isError ? (
        <ErrorState error={scans.error} retry={() => void scans.refetch()} />
      ) : scans.data?.items.length ? (
        <Panel
          title="Recent scans"
          note="Open a scan to see live progress or partial results as they stream in."
        >
          <div className="scan-list">
            {scans.data.items.map((scan) => (
              <ScanRow key={scan.id} scan={scan} />
            ))}
          </div>
        </Panel>
      ) : (
        <Empty
          title="Nothing has been scanned"
          icon="🔍"
          action={
            <button className="primary" onClick={() => setFormOpen(true)}>
              Launch a first scan
            </button>
          }
        >
          Start with a Git repository, container image, cloud account, or approved local target.
          A scan turns evidence into a prioritised migration view.
        </Empty>
      )}
    </Page>
  );
}

// ─── Scan wizard (§9.5a — launchable by filling one field) ───────────────────

interface ScanFormProps {
  capabilities: Array<{ kind: string; scanner: string }>;
  pending: boolean;
  error: unknown;
  close: () => void;
  submit: (value: Record<string, unknown>) => void;
}

function ScanForm({ capabilities, pending, error, close, submit }: ScanFormProps) {
  const [kind, setKind] = useState(capabilities[0]?.kind ?? "git_repository");
  const scanner = capabilities.find((item) => item.kind === kind)?.scanner ?? "source";

  const onSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    submit({
      target_kind: kind,
      target_identifier: String(form.get("target_identifier")),
      target_reference: String(form.get("target_reference")) || null,
      display_name: String(form.get("display_name")) || null,
      scanners: [scanner],
    });
  };

  return (
    <section
      className="dialog-backdrop"
      role="presentation"
      onClick={(event) => {
        if (event.target === event.currentTarget) close();
      }}
    >
      <form className="dialog" onSubmit={onSubmit} aria-label="Launch scan">
        <header>
          <div>
            <p className="eyebrow">NEW DISCOVERY</p>
            <h2>What should Trinetra inspect?</h2>
          </div>
          <button type="button" className="icon-button" aria-label="Close" onClick={close}>
            ×
          </button>
        </header>

        {/* §9.5a — target type selector */}
        <label>
          Target type
          <select value={kind} onChange={(event) => setKind(event.target.value)}>
            {(capabilities.length
              ? capabilities
              : [{ kind: "git_repository", scanner: "source" }]
            ).map((item) => (
              <option key={item.kind} value={item.kind}>
                {titleCase(item.kind)}
              </option>
            ))}
          </select>
        </label>

        {/* §4.11d — one required field; sane defaults on everything else */}
        <label>
          Target address <span className="required-mark">*</span>
          <input
            id="scan-target-input"
            name="target_identifier"
            required
            placeholder={
              kind === "git_repository"
                ? "https://github.com/org/repository"
                : kind === "container_image"
                  ? "nginx:latest"
                  : "Target identifier"
            }
          />
        </label>

        <label>
          Reference <span className="field-optional">(optional)</span>
          <input
            name="target_reference"
            placeholder={kind === "git_repository" ? "main, v1.2.3, or commit SHA" : "tag or digest"}
          />
        </label>

        <label>
          Display name <span className="field-optional">(optional)</span>
          <input name="display_name" placeholder='e.g. "Payments API"' />
        </label>

        <p className="help">
          Scanner: <b>{titleCase(scanner)}</b>. Partial results stream into the Explorer while the
          scan runs — you do not need to wait for it to finish.
        </p>

        {!!error && (
          <p className="form-error" role="alert">
            {problem(error)}
          </p>
        )}

        <footer>
          <button type="button" onClick={close}>
            Cancel
          </button>
          <button id="scan-launch-submit" className="primary" disabled={pending}>
            {pending ? "Queueing…" : "Launch scan"}
          </button>
        </footer>
      </form>
    </section>
  );
}

function ScanRow({ scan }: { scan: Scan }) {
  return (
    <Link className="scan-row" to={`/scans/${scan.id}`}>
      <span className={`status status-${scan.status}`}>{titleCase(scan.status)}</span>
      <div>
        <b>{scan.display_name || scan.target_identifier}</b>
        <small>
          {titleCase(scan.target_kind)} · {formatDate(scan.created_at)}
        </small>
      </div>
      <span className="scan-count">{scan.artefact_count.toLocaleString()} artefacts</span>
      <span className="scan-chevron" aria-hidden="true">›</span>
    </Link>
  );
}
