import { useMemo } from "react";
import { createApi } from "../api/client";
import { useAuth } from "./useAuth";

/** Returns a typed API client scoped to the active project and auth token. */
export function useApi() {
  const { token, csrf, project } = useAuth();
  return useMemo(
    () => createApi({ accessToken: token, csrfToken: csrf, projectId: project?.id }),
    [token, csrf, project?.id],
  );
}
