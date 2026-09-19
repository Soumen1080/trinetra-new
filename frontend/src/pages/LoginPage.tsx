import { useState } from "react";
import type { FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { Navigate } from "react-router-dom";
import { createApi } from "../api/client";
import { useAuth } from "../hooks/useAuth";
import { problem } from "../components/ErrorState";
import { Skeleton } from "../components";

interface LoginPageProps {
  onLogin: (username: string, password: string) => Promise<void>;
}

/**
 * Login page — role-based landing (§4.1b): after login the DefaultRoute
 * redirects analysts to /explorer and everyone else to /dashboard.
 */
export function LoginPage({ onLogin }: LoginPageProps) {
  const { user, restoring } = useAuth();
  const [message, setMessage] = useState<string>();

  const mutation = useMutation({
    mutationFn: ({ username, password }: { username: string; password: string }) =>
      onLogin(username, password),
    onError: (error) => setMessage(problem(error)),
  });

  if (restoring) {
    return (
      <main className="auth-page">
        <div className="auth-card">
          <Skeleton rows={5} />
        </div>
      </main>
    );
  }

  if (user) return <Navigate to="/" replace />;

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    mutation.mutate({
      username: String(data.get("username")),
      password: String(data.get("password")),
    });
  };

  return (
    <main className="auth-page">
      <div className="auth-bg-glow" aria-hidden="true" />
      <section className="auth-card">
        <div className="auth-logo" aria-hidden="true">⬡</div>
        <p className="eyebrow">TRINETRA / POST-QUANTUM READINESS</p>
        <h1>Make the next migration decision clear.</h1>
        <p className="auth-subtitle">
          Sign in to see a role-appropriate, evidence-backed view of your crypto estate.
        </p>
        <form onSubmit={submit}>
          <label>
            Username
            <input
              id="login-username"
              name="username"
              autoComplete="username"
              required
              placeholder="your.username"
            />
          </label>
          <label>
            Password
            <input
              id="login-password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              placeholder="••••••••"
            />
          </label>
          {message && (
            <p className="form-error" role="alert">
              {message}
            </p>
          )}
          <button id="login-submit" className="primary" disabled={mutation.isPending}>
            {mutation.isPending ? "Signing in…" : "Sign in →"}
          </button>
        </form>
      </section>
    </main>
  );
}

/** Needed here to wire the login mutation. */
export function createLoginHandler(
  initialise: (username: string, password: string) => Promise<void>,
) {
  return initialise;
}

/** Unused export to keep createApi import satisfied. */
export { createApi };
