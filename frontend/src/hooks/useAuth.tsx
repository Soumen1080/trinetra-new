import { createContext, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { Project, User, createApi } from "../api/client";

export type Auth = {
  user: User | null;
  token?: string;
  csrf?: string;
  project: Project | null;
  projects: Project[];
  restoring: boolean;
  setProject: (project: Project) => void;
  signOut: () => Promise<void>;
};

const AuthContext = createContext<Auth | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string>();
  const [csrf, setCsrf] = useState<string>();
  const [projects, setProjects] = useState<Project[]>([]);
  const [project, setProject] = useState<Project | null>(null);
  const [restoring, setRestoring] = useState(true);

  const api = useMemo(
    () => createApi({ accessToken: token, csrfToken: csrf, projectId: project?.id }),
    [token, csrf, project?.id],
  );

  const initialise = async (currentUser: User, nextToken?: string, nextCsrf?: string) => {
    setUser(currentUser);
    setToken(nextToken);
    setCsrf(nextCsrf);
    const nextProjects = await createApi({ accessToken: nextToken, csrfToken: nextCsrf }).projects();
    setProjects(nextProjects);
    setProject(nextProjects[0] ?? null);
  };

  useEffect(() => {
    createApi()
      .session()
      .then((session) => initialise(session.user, undefined, session.csrf_token))
      .catch(() => setUser(null))
      .finally(() => setRestoring(false));
  }, []);

  const signOut = async () => {
    try {
      await api.logout();
    } finally {
      setUser(null);
      setToken(undefined);
      setCsrf(undefined);
      setProject(null);
      setProjects([]);
    }
  };

  const value: Auth = { user, token, csrf, project, projects, restoring, setProject, signOut };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): Auth {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside <AuthProvider>.");
  return value;
}
