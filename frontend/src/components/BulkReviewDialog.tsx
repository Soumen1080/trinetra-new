import { useState } from "react";
import type { FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { useApi } from "../hooks/useApi";
import { problem } from "./ErrorState";

interface BulkReviewDialogProps {
  artefactIds: string[];
  close: () => void;
  done: () => void;
}

/**
 * Bulk review dialog (§9.6f) — accept risk, assign owner, mark false positive.
 * Reason is required for accept-risk and false-positive actions, so the
 * disposition is always auditable (§4.6e — it sticks across rescans).
 */
export function BulkReviewDialog({ artefactIds, close, done }: BulkReviewDialogProps) {
  const api = useApi();
  const [action, setAction] = useState("accept_risk");
  const [message, setMessage] = useState<string>();

  const mutation = useMutation({
    mutationFn: (payload: { artefact_ids: string[]; action: string; owner?: string; reason?: string }) =>
      api.bulkReview(payload),
    onSuccess: done,
    onError: (error) => setMessage(problem(error)),
  });

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    mutation.mutate({
      artefact_ids: artefactIds,
      action,
      owner: String(form.get("owner") || "") || undefined,
      reason: String(form.get("reason") || "") || undefined,
    });
  };

  const needsReason = action === "accept_risk" || action === "false_positive";

  return (
    <section
      className="dialog-backdrop"
      role="presentation"
      onClick={(event) => {
        if (event.target === event.currentTarget) close();
      }}
    >
      <form className="dialog" onSubmit={submit} aria-label="Review selected artefacts">
        <header>
          <div>
            <p className="eyebrow">BULK REVIEW</p>
            <h2>
              Update {artefactIds.length} artefact{artefactIds.length === 1 ? "" : "s"}
            </h2>
          </div>
          <button type="button" className="icon-button" onClick={close} aria-label="Close">
            ×
          </button>
        </header>

        <label>
          Action
          <select value={action} onChange={(event) => setAction(event.target.value)}>
            <option value="accept_risk">Accept risk</option>
            <option value="assign_owner">Assign owner</option>
            <option value="false_positive">Mark false positive</option>
            <option value="clear">Clear prior review</option>
          </select>
        </label>

        {action === "assign_owner" && (
          <label>
            Owner
            <input name="owner" required placeholder="Team or person responsible" />
          </label>
        )}

        {needsReason && (
          <label>
            Reason
            <textarea
              name="reason"
              required
              placeholder={
                action === "false_positive"
                  ? "Why this is not a production finding"
                  : "Why this risk is being accepted — e.g. compensating control"
              }
            />
          </label>
        )}

        <p className="help">
          This is a project-scoped, audited disposition. It persists after later rescans (§4.6e).
        </p>

        {message && (
          <p className="form-error" role="alert">
            {message}
          </p>
        )}

        <footer>
          <button type="button" onClick={close}>
            Cancel
          </button>
          <button className="primary" disabled={mutation.isPending}>
            {mutation.isPending ? "Saving…" : "Save review"}
          </button>
        </footer>
      </form>
    </section>
  );
}
