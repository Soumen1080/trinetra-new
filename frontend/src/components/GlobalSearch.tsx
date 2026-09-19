import { useState } from "react";
import type { KeyboardEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { problem } from "./ErrorState";
import { Skeleton } from "./Skeleton";
import { RiskBadge } from "./RiskBadge";
import { titleCase } from "../risk";

interface GlobalSearchProps {
  close: () => void;
}

/**
 * Full-screen search palette (§4.7e — / or Ctrl-K from anywhere).
 * - Debounced at ≥ 2 characters
 * - Keyboard: Arrow keys to navigate, Enter to open, Esc to close
 */
export function GlobalSearch({ close }: GlobalSearchProps) {
  const api = useApi();
  const { project } = useAuth();
  const [value, setValue] = useState("");
  const [cursor, setCursor] = useState(0);
  const navigate = useNavigate();

  const search = useQuery({
    queryKey: ["global-search", project?.id, value],
    queryFn: () => api.artefacts({ q: value, limit: 12 }),
    enabled: !!project && value.trim().length >= 2,
  });

  const results = search.data?.items ?? [];

  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Escape") {
      close();
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      setCursor((c) => Math.min(c + 1, results.length - 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setCursor((c) => Math.max(c - 1, 0));
    } else if (event.key === "Enter" && results[cursor]) {
      navigate(`/artefacts/${results[cursor].id}`);
      close();
    }
  };

  return (
    <section
      className="dialog-backdrop"
      role="presentation"
      onClick={(event) => {
        if (event.target === event.currentTarget) close();
      }}
    >
      <div className="search-dialog" role="dialog" aria-modal="true" aria-label="Search artefacts">
        <header>
          <span>Search the project</span>
          <div className="search-hints">
            <kbd>↑↓</kbd>
            <span>navigate</span>
            <kbd>↵</kbd>
            <span>open</span>
            <kbd>Esc</kbd>
            <span>close</span>
          </div>
        </header>
        <input
          id="global-search-input"
          autoFocus
          value={value}
          onKeyDown={handleKeyDown}
          onChange={(event) => {
            setValue(event.target.value);
            setCursor(0);
          }}
          placeholder="Artefact name, algorithm, location…"
          aria-label="Search artefacts"
          aria-autocomplete="list"
          aria-controls="search-results"
        />
        <div id="search-results" role="listbox" aria-label="Search results">
          {value.length < 2 ? (
            <p className="muted search-hint-text">Type at least 2 characters to search.</p>
          ) : search.isPending ? (
            <Skeleton rows={3} />
          ) : search.isError ? (
            <p className="form-error">{problem(search.error)}</p>
          ) : results.length ? (
            <ul>
              {results.map((item, index) => (
                <li key={item.id} role="option" aria-selected={index === cursor}>
                  <button
                    className={index === cursor ? "active" : ""}
                    onClick={() => {
                      navigate(`/artefacts/${item.id}`);
                      close();
                    }}
                  >
                    <RiskBadge priority={item.priority} />
                    <span>
                      <b>{item.name}</b>
                      <small>{item.location || titleCase(item.type)}</small>
                    </span>
                    <span className="search-arrow" aria-hidden="true">→</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted search-hint-text">No artefacts match that search.</p>
          )}
        </div>
      </div>
    </section>
  );
}
