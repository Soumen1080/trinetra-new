import { Navigate, Outlet, Route, Routes, useNavigate } from "react-router-dom";
import { useMemo } from "react";
import { createApi } from "./api/client";
import { AuthProvider, useAuth } from "./hooks/useAuth";
import { Shell } from "./Shell";
import { Skeleton } from "./components";
import { LoginPage } from "./pages/LoginPage";
import { DashboardPage } from "./pages/DashboardPage";
import { ScansPage } from "./pages/ScansPage";
import { ScanDetailPage } from "./pages/ScanDetailPage";
import { ExplorerPage } from "./pages/ExplorerPage";
import { ArtefactPage } from "./pages/ArtefactPage";
import { GlossaryPage } from "./pages/GlossaryPage";

/**
 * Root application component.
 *
 * Responsibilities:
 * - Wrap the tree in AuthProvider
 * - Define all routes
 * - Nothing else — all logic lives in page/component files
 */
function App() {
  return (
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  );
}

function AppRoutes() {
  const navigate = useNavigate();
  const auth = useAuth();

  /** Login handler — wires into the session initialisation flow. */
  const handleLogin = useMemo(
    () => async (username: string, password: string) => {
      const result = await createApi().login(username, password);
      // Reinitialise auth state via the provider
      // The AuthProvider handles setUser/setToken internally via session check.
      // We navigate after a successful login.
      const nextApi = createApi({ accessToken: result.access_token, csrfToken: result.csrf_token });
      const projects = await nextApi.projects();
      // The provider will re-read from the session cookie; trigger by navigating.
      void projects;
      navigate("/", { replace: true });
      // Force a session reload via the provider's session() call.
      window.location.replace("/");
    },
    [navigate],
  );

  return (
    <Routes>
      <Route
        path="/login"
        element={
          <LoginPage
            onLogin={async (username, password) => {
              const result = await createApi().login(username, password);
              // Store token then re-init via full session restore
              void result;
              await createApi({
                accessToken: result.access_token,
                csrfToken: result.csrf_token,
              }).projects();
              window.location.replace("/");
            }}
          />
        }
      />
      <Route element={<Protected />}>
        <Route element={<Shell />}>
          <Route index element={<DefaultRoute />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="scans/:scanId" element={<ScanDetailPage />} />
          <Route path="explorer" element={<ExplorerPage />} />
          <Route path="artefacts/:artefactId" element={<ArtefactPage />} />
          <Route path="glossary" element={<GlossaryPage />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

/** Redirects unauthenticated users to /login, shows skeleton while restoring. */
function Protected() {
  const { user, restoring } = useAuth();
  if (restoring)
    return (
      <main className="page">
        <Skeleton rows={7} />
      </main>
    );
  return user ? <Outlet /> : <Navigate to="/login" replace />;
}

/**
 * §4.1b — role-based default landing page:
 * analysts → Explorer (their working surface), everyone else → Dashboard.
 */
function DefaultRoute() {
  const { user } = useAuth();
  return <Navigate to={user?.role === "analyst" ? "/explorer" : "/dashboard"} replace />;
}

export default App;
