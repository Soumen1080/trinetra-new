import { ApiError } from "../api/client";

function problem(error: unknown): string {
  if (error instanceof ApiError) {
    const recovery =
      error.status === 401
        ? "Sign in again."
        : error.status === 403
          ? "Choose a project you can access."
          : "Check the input and try again.";
    return `${error.message} ${recovery}`;
  }
  return "We could not load this data. Check your connection and retry.";
}

/** Re-export so callers that already import from this module can use problem(). */
export { problem };

interface ErrorStateProps {
  error: unknown;
  retry: () => void;
}

/**
 * Error display following §4.5e: states the cause AND the fix — never
 * a stack trace or raw error code.
 */
export function ErrorState({ error, retry }: ErrorStateProps) {
  return (
    <section className="error-state" role="alert">
      <div className="error-state-icon" aria-hidden="true">⚠</div>
      <div>
        <h2>Something needs attention</h2>
        <p>{problem(error)}</p>
        <button onClick={retry}>Try again</button>
      </div>
    </section>
  );
}
