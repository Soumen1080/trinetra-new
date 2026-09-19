import type { components, paths } from "./openapi.generated";

/** The generated OpenAPI document is the source of truth for these aliases. */
export type OpenApiPaths = paths;
export type Artefact = components["schemas"]["ArtefactListItem"];
export type ArtefactList = components["schemas"]["ArtefactListResponse"];
export type Scan = components["schemas"]["ScanResponse"];
export type ScanList = components["schemas"]["ScanListResponse"];
export type Dashboard = components["schemas"]["DashboardSummary"];
export type Project = components["schemas"]["ProjectResponse"];
export type User = components["schemas"]["UserResponse"];
export type LoginResult = components["schemas"]["TokenResponse"];
export type SessionResult = components["schemas"]["SessionResponse"];

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export type ApiContext = {
  accessToken?: string;
  csrfToken?: string;
  projectId?: string;
};

type RequestOptions = Omit<RequestInit, "body"> & { body?: unknown; mutation?: boolean };

const apiRoot = import.meta.env.VITE_API_BASE_URL ?? "/api";

function messageFrom(body: unknown, fallback: string) {
  if (typeof body === "object" && body !== null && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (typeof detail === "object" && detail !== null && "message" in detail) {
      const message = (detail as { message: unknown }).message;
      if (typeof message === "string") return message;
    }
  }
  return fallback;
}

function codeFrom(body: unknown) {
  if (typeof body === "object" && body !== null && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "object" && detail !== null && "code" in detail) {
      const code = (detail as { code: unknown }).code;
      if (typeof code === "string") return code;
    }
  }
  return "REQUEST_FAILED";
}

function query(params: Record<string, string | number | undefined | null>) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const suffix = search.toString();
  return suffix ? `?${suffix}` : "";
}

export function createApi(context: ApiContext = {}) {
  async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const headers = new Headers(options.headers);
    headers.set("Accept", "application/json");
    if (context.accessToken) headers.set("Authorization", `Bearer ${context.accessToken}`);
    if (context.projectId) headers.set("X-Project-ID", context.projectId);
    if (options.mutation && context.csrfToken) headers.set("X-CSRF-Token", context.csrfToken);
    let body: BodyInit | undefined;
    if (options.body !== undefined) {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(options.body);
    }
    const response = await fetch(`${apiRoot}${path}`, {
      ...options,
      headers,
      body,
      credentials: "include",
    });
    if (response.status === 204) return undefined as T;
    const data: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      throw new ApiError(response.status, codeFrom(data), messageFrom(data, `Request failed (${response.status}).`));
    }
    return data as T;
  }

  return {
    login: (username: string, password: string) =>
      request<LoginResult>("/auth/login", { method: "POST", body: { username, password }, mutation: true }),
    logout: () => request<void>("/auth/logout", { method: "POST", mutation: true }),
    session: () => request<SessionResult>("/auth/session"),
    projects: () => request<Project[]>("/projects"),
    dashboard: () => request<Dashboard>("/dashboard/summary"),
    scans: (offset = 0, limit = 25) => request<ScanList>(`/scans${query({ offset, limit })}`),
    scan: (scanId: string) => request<Scan>(`/scans/${scanId}`),
    capabilities: () => request<{ targets: Array<{ kind: string; scanner: string }> }>("/scans/capabilities"),
    createScan: (payload: Record<string, unknown>) =>
      request<Scan>("/scans", { method: "POST", body: payload, mutation: true }),
    cancelScan: (scanId: string) => request<Scan>(`/scans/${scanId}/cancel`, { method: "POST", mutation: true }),
    progress: (scanId: string) => request<{ percent: number; stage: string; counts: Record<string, number>; message?: string }>(`/scans/${scanId}/progress`),
    scanArtefacts: (scanId: string, params: Record<string, string | number | undefined | null>) =>
      request<ArtefactList>(`/scans/${scanId}/artefacts${query(params)}`),
    artefacts: (params: Record<string, string | number | undefined | null>) =>
      request<ArtefactList>(`/artefacts${query(params)}`),
    artefact: (artefactId: string) => request<ArtefactDetail>(`/artefacts/${artefactId}`),
    risk: (artefactId: string) => request<{ assessment: Assessment | null; message?: string }>(`/artefacts/${artefactId}/risk`),
    mosca: (artefactId: string) => request<{ mosca: Mosca | null; input_provenance: Record<string, unknown>; message?: string }>(`/artefacts/${artefactId}/mosca`),
    whatIf: (artefactId: string, payload: Record<string, unknown>) =>
      request<{ assessment: Assessment }>(`/artefacts/${artefactId}/what-if`, { method: "POST", body: payload, mutation: true }),
    updateContext: (artefactId: string, payload: Record<string, unknown>) =>
      request<unknown>(`/artefacts/${artefactId}/context`, { method: "PATCH", body: payload, mutation: true }),
    bulkReview: (payload: { artefact_ids: string[]; action: string; owner?: string; reason?: string }) =>
      request<{ updated: number }>("/artefacts/bulk-review", { method: "POST", body: payload, mutation: true }),
    createReport: (scanId: string, format: string) =>
      request<{ id: string; format: string }>(`/scans/${scanId}/reports`, { method: "POST", body: { format }, mutation: true }),
    reportUrl: (_scanId: string, reportId: string) => `${apiRoot}/reports/${reportId}`,
    downloadReport: async (reportId: string) => {
      const headers = new Headers({ Accept: "application/octet-stream" });
      if (context.accessToken) headers.set("Authorization", `Bearer ${context.accessToken}`);
      if (context.projectId) headers.set("X-Project-ID", context.projectId);
      const response = await fetch(`${apiRoot}/reports/${reportId}`, { headers, credentials: "include" });
      if (!response.ok) {
        const data: unknown = await response.json().catch(() => undefined);
        throw new ApiError(response.status, codeFrom(data), messageFrom(data, `Download failed (${response.status}).`));
      }
      const name = response.headers.get("content-disposition")?.match(/filename="?([^";]+)"?/)?.[1] ?? "trinetra-report";
      return { blob: await response.blob(), name };
    },
  };
}

export type Assessment = {
  final_score?: number | null;
  priority?: string;
  status?: string;
  factors?: Record<string, number | string | null>;
  mosca?: Mosca | null;
  [key: string]: unknown;
};
export type Mosca = { x_years?: number | null; y_years?: number | null; z_years?: number | null; migration_deadline_year?: number | null; [key: string]: unknown };
export type ArtefactDetail = {
  artefact: Artefact;
  detail: Record<string, unknown> | null;
  evidence: Array<Record<string, unknown>>;
  raw_cbom: Record<string, unknown> | null;
  context: Record<string, unknown> | null;
  assessments: Assessment[];
  recommendations: Array<Record<string, unknown>>;
};
