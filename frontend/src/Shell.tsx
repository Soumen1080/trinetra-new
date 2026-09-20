import { useEffect, useState } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";
import { useAuth } from "./hooks/useAuth";
import { GlobalSearch } from "./components/GlobalSearch";
import {
  GuidedTour,
  AccessibilityMenu,
  ColorBlindFilters,
  PersonaSwitcher,
  DemoDataLoader,
} from "./components";

/**
 * App shell — persistent sidebar, topbar, theme toggle, project picker (§4.7a).
 * Global search opens on Ctrl-K or / (§4.7e).
 * Mounts Phase 10B Guided Tour (§4.11a), A11y Suite (§4.9), and Persona Switcher (§4.1b).
 */
export function Shell() {
  const { user, project, projects, setProject, signOut } = useAuth();
  const [theme, setTheme] = useState<"light" | "dark">(() =>
    matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light",
  );
  const [searchOpen, setSearchOpen] = useState(false);
  const [tourOpen, setTourOpen] = useState(false);

  // Apply theme to <html>
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  // Ctrl-K or / opens global search (§4.7e)
  useEffect(() => {
    const handler = (event: globalThis.KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const editing = target?.matches("input, textarea, select, [contenteditable='true']");
      if (
        ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") ||
        (event.key === "/" && !editing)
      ) {
        event.preventDefault();
        setSearchOpen(true);
      }
      if (event.key === "Escape") setSearchOpen(false);
    };
    addEventListener("keydown", handler);
    return () => removeEventListener("keydown", handler);
  }, []);

  return (
    <>
      <div className="shell">
        {/* §4.7a — persistent left nav */}
        <aside className="sidebar" aria-label="Primary navigation">
          <Link className="brand" to="/" aria-label="Trinetra home">
            <span className="brand-logo" aria-hidden="true">⬡</span>
            <span>
              TRINETRA
              <small>READINESS</small>
            </span>
          </Link>

          <nav>
            <NavLink to="/dashboard" id="nav-dashboard">
              <span className="nav-icon" aria-hidden="true">◉</span>
              Overview
            </NavLink>
            <NavLink to="/risk" id="nav-risk">
              <span className="nav-icon" aria-hidden="true">▲</span>
              Risk Visuals
            </NavLink>
            <NavLink to="/migration" id="nav-migration">
              <span className="nav-icon" aria-hidden="true">⮞</span>
              Migration
            </NavLink>
            <NavLink to="/scans" id="nav-scans">
              <span className="nav-icon" aria-hidden="true">⬡</span>
              Scans
            </NavLink>
            <NavLink to="/explorer" id="nav-explorer">
              <span className="nav-icon" aria-hidden="true">⊞</span>
              Explorer
            </NavLink>
            <NavLink to="/glossary" id="nav-glossary">
              <span className="nav-icon" aria-hidden="true">⊕</span>
              Glossary
            </NavLink>
          </nav>

          <div className="side-bottom">
            <label className="project-picker">
              <span className="picker-label">Project</span>
              <select
                value={project?.id ?? ""}
                onChange={(event) => {
                  const selected = projects.find((item) => item.id === event.target.value);
                  if (selected) setProject(selected);
                }}
                aria-label="Active project"
              >
                <option value="" disabled>
                  {projects.length ? "Select project" : "No project available"}
                </option>
                {projects.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </label>

            <button
              className="quiet"
              onClick={() => setTheme(theme === "light" ? "dark" : "light")}
              aria-label={`Switch to ${theme === "light" ? "dark" : "light"} mode`}
            >
              {theme === "light" ? "🌙 Dark mode" : "☀ Light mode"}
            </button>

            <button className="quiet" onClick={() => void signOut()}>
              Sign out · <b>{user?.username}</b>
            </button>
          </div>
        </aside>

        {/* Main content area */}
        <main className="content">
          <header className="topbar">
            <div className="topbar-breadcrumb">
              <p className="breadcrumb">
                Trinetra / {project?.name ?? <em className="muted">No project selected</em>}
              </p>
            </div>

            <div className="topbar-actions" style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <PersonaSwitcher />

              <button
                className="button quiet"
                style={{ fontSize: "0.82rem", display: "inline-flex", alignItems: "center", gap: "0.3rem" }}
                onClick={() => setTourOpen(true)}
                aria-label="Start guided product tour (§4.11a)"
                title="Interactive 4-screen tour of Trinetra (§4.11a)"
              >
                <span>🎯</span>
                <span>Tour</span>
              </button>

              <DemoDataLoader variant="quiet" />

              <AccessibilityMenu />

              <button
                className="search-trigger"
                onClick={() => setSearchOpen(true)}
                aria-keyshortcuts="Control+K Meta+K /"
                aria-label="Open search"
              >
                Search artefacts{" "}
                <kbd aria-label="keyboard shortcut">Ctrl K</kbd>
              </button>
            </div>
          </header>

          <Outlet />
        </main>
      </div>

      {/* Cross-cutting utilities */}
      <ColorBlindFilters />
      <GuidedTour isOpen={tourOpen} onClose={() => setTourOpen(false)} />
      {searchOpen && <GlobalSearch close={() => setSearchOpen(false)} />}
    </>
  );
}
