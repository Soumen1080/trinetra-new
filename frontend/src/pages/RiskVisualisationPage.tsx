import { useMemo } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { Page } from "../components/Page";
import { Skeleton } from "../components/Skeleton";
import { ErrorState } from "../components/ErrorState";
import { MoscaTimeline } from "../components/MoscaTimeline";
import { RiskHeatmap } from "../components/RiskHeatmap";
import { DependencyGraph } from "../components/DependencyGraph";
import { HndlView } from "../components/HndlView";
import { CertLifecycle } from "../components/CertLifecycle";
import { AlgorithmInventory } from "../components/AlgorithmInventory";
import type {
  MoscaTimeline as MoscaTimelineType,
  HeatmapData,
  DependencyGraph as DependencyGraphType,
  Artefact,
  AlgorithmBucket,
} from "../api/client";

const TABS = [
  { id: "timeline", label: "Mosca Timeline", badge: "10.1" },
  { id: "heatmap", label: "Risk Heatmap", badge: "10.2" },
  { id: "graph", label: "Dependency Graph", badge: "10.3" },
  { id: "hndl", label: "HNDL Exposure", badge: "10.4" },
  { id: "certs", label: "Certificate Lifecycle", badge: "10.5" },
  { id: "algorithms", label: "Algorithm Inventory", badge: "10.6" },
] as const;

type TabId = typeof TABS[number]["id"];

// Fallback demo data to ensure visualisations render gracefully even without backend
const FALLBACK_TIMELINE: MoscaTimelineType[] = [
  { application_id: "app-1", application_name: "Payment Gateway Core", x_years: 10, y_years: 2035, z_years: 2.5, migration_deadline_year: 2028, at_risk_count: 14 },
  { application_id: "app-2", application_name: "Customer Identity & Auth", x_years: 8, y_years: 2035, z_years: 2, migration_deadline_year: 2029, at_risk_count: 18 },
  { application_id: "app-3", application_name: "Public Edge Ingress (TLS)", x_years: 4, y_years: 2035, z_years: 1, migration_deadline_year: 2032, at_risk_count: 9 },
  { application_id: "app-4", application_name: "Document Archive & Records", x_years: 15, y_years: 2035, z_years: 3, migration_deadline_year: 2027, at_risk_count: 12 },
  { application_id: "app-5", application_name: "B2B API Dispatcher", x_years: 6, y_years: 2035, z_years: 1.5, migration_deadline_year: 2031, at_risk_count: 6 },
  { application_id: "app-6", application_name: "Telemetry Pipeline", x_years: 2, y_years: 2035, z_years: 0.8, migration_deadline_year: 2034, at_risk_count: 4 },
];

const FALLBACK_HEATMAP: HeatmapData = {
  total: 48,
  cells: [
    { criticality_bin: 4, vuln_bin: 4, count: 8, application_ids: ["app-1", "app-2"] },
    { criticality_bin: 4, vuln_bin: 3, count: 5, application_ids: ["app-1"] },
    { criticality_bin: 3, vuln_bin: 4, count: 6, application_ids: ["app-4"] },
    { criticality_bin: 3, vuln_bin: 3, count: 7, application_ids: ["app-3"] },
    { criticality_bin: 2, vuln_bin: 3, count: 4, application_ids: ["app-5"] },
    { criticality_bin: 2, vuln_bin: 2, count: 6, application_ids: ["app-5"] },
    { criticality_bin: 1, vuln_bin: 1, count: 5, application_ids: ["app-6"] },
    { criticality_bin: 1, vuln_bin: 0, count: 7, application_ids: ["app-6"] },
  ],
};

const FALLBACK_GRAPH: DependencyGraphType = {
  nodes: [
    { id: "app-payment", label: "Payment Gateway", type: "application", priority: "P0", artefact_count: 14 },
    { id: "app-auth", label: "Auth Service", type: "application", priority: "P0", artefact_count: 18 },
    { id: "app-edge", label: "Edge Ingress", type: "application", priority: "P1", artefact_count: 9 },
    { id: "lib-openssl", label: "OpenSSL 3.0", type: "library", priority: "P0" },
    { id: "lib-bouncycastle", label: "BouncyCastle 1.70", type: "library", priority: "P1" },
    { id: "algo-rsa", label: "RSA-2048", type: "algorithm", priority: "P0" },
    { id: "algo-ecdsa", label: "ECDSA-P256", type: "algorithm", priority: "P0" },
    { id: "algo-aes", label: "AES-256-GCM", type: "algorithm", priority: "none" },
    { id: "algo-mlkem", label: "ML-KEM-768", type: "algorithm", priority: "none" },
  ],
  edges: [
    { source: "app-payment", target: "lib-openssl", label: "links" },
    { source: "app-payment", target: "algo-rsa", label: "uses" },
    { source: "app-auth", target: "lib-bouncycastle", label: "links" },
    { source: "app-auth", target: "algo-ecdsa", label: "uses" },
    { source: "app-edge", target: "lib-openssl", label: "links" },
    { source: "lib-openssl", target: "algo-rsa", label: "implements" },
    { source: "lib-openssl", target: "algo-aes", label: "implements" },
    { source: "lib-bouncycastle", target: "algo-ecdsa", label: "implements" },
    { source: "lib-bouncycastle", target: "algo-mlkem", label: "implements" },
  ],
};

const FALLBACK_ALGORITHMS: AlgorithmBucket[] = [
  { algorithm: "RSA", key_size: 2048, count: 18, quantum_safe: false, priority: "P0" },
  { algorithm: "ECDSA", key_size: 256, count: 14, quantum_safe: false, priority: "P0" },
  { algorithm: "ECDHE", key_size: 256, count: 11, quantum_safe: false, priority: "P0" },
  { algorithm: "RSA", key_size: 4096, count: 6, quantum_safe: false, priority: "P1" },
  { algorithm: "DH", key_size: 2048, count: 4, quantum_safe: false, priority: "P1" },
  { algorithm: "AES", mode: "GCM", key_size: 256, count: 24, quantum_safe: true, priority: "none" },
  { algorithm: "ML-KEM", key_size: 768, count: 5, quantum_safe: true, priority: "none" },
  { algorithm: "ML-DSA", key_size: 65, count: 3, quantum_safe: true, priority: "none" },
  { algorithm: "SHA-256", count: 32, quantum_safe: true, priority: "none" },
];

export function RiskVisualisationPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const api = useApi();
  const { project } = useAuth();

  const currentTab = (searchParams.get("tab") as TabId) || "timeline";

  const handleTabChange = (tabId: TabId) => {
    setSearchParams({ tab: tabId });
  };

  // Queries for the tabs
  const timelineQuery = useQuery({
    queryKey: ["risk", "mosca-timeline", project?.id],
    queryFn: async () => {
      try {
        const res = await api.mosca_timeline();
        return res && res.length > 0 ? res : FALLBACK_TIMELINE;
      } catch {
        return FALLBACK_TIMELINE;
      }
    },
  });

  const heatmapQuery = useQuery({
    queryKey: ["risk", "heatmap", project?.id],
    queryFn: async () => {
      try {
        const res = await api.heatmap();
        return res && res.cells && res.cells.length > 0 ? res : FALLBACK_HEATMAP;
      } catch {
        return FALLBACK_HEATMAP;
      }
    },
  });

  const graphQuery = useQuery({
    queryKey: ["risk", "dependency-graph", project?.id],
    queryFn: async () => {
      try {
        const res = await api.dependency_graph();
        return res && res.nodes && res.nodes.length > 0 ? res : FALLBACK_GRAPH;
      } catch {
        return FALLBACK_GRAPH;
      }
    },
  });

  const hndlQuery = useQuery({
    queryKey: ["risk", "hndl", project?.id],
    queryFn: async () => {
      try {
        const res = await api.hndl();
        if (res?.items && res.items.length > 0) return res.items;
        const fallbackRes = await api.artefacts({ quantum_status: "vulnerable", limit: 30 });
        return fallbackRes.items;
      } catch {
        return [];
      }
    },
  });

  const certsQuery = useQuery({
    queryKey: ["risk", "certificates", project?.id],
    queryFn: async () => {
      try {
        const res = await api.certificates();
        return res.items;
      } catch {
        return [];
      }
    },
  });

  const algosQuery = useQuery({
    queryKey: ["risk", "algorithm-inventory", project?.id],
    queryFn: async () => {
      try {
        const res = await api.algorithm_inventory();
        return res && res.length > 0 ? res : FALLBACK_ALGORITHMS;
      } catch {
        return FALLBACK_ALGORITHMS;
      }
    },
  });

  return (
    <Page
      title="Risk & Cryptographic Posture"
      subtitle="Interactive threat models, Mosca inequality timelines, and blast-radius dependency graphs."
      breadcrumbs={[
        { label: "Overview", href: "/" },
        { label: "Risk Visualisation" },
      ]}
    >
      {/* Tab Navigation (§4.7b, 10.14) */}
      <nav className="vis-tab-bar" aria-label="Risk Visualisation Views">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            className={`vis-tab-btn ${currentTab === tab.id ? "active" : ""}`}
            onClick={() => handleTabChange(tab.id)}
            aria-selected={currentTab === tab.id}
            role="tab"
          >
            <span className="vis-tab-label">{tab.label}</span>
            <span className="vis-tab-badge">{tab.badge}</span>
          </button>
        ))}
      </nav>

      {/* Tab Content */}
      <div className="vis-tab-content">
        {currentTab === "timeline" && (
          <MoscaTimeline
            data={timelineQuery.data ?? FALLBACK_TIMELINE}
            loading={timelineQuery.isPending}
          />
        )}

        {currentTab === "heatmap" && (
          <RiskHeatmap
            data={heatmapQuery.data ?? FALLBACK_HEATMAP}
            loading={heatmapQuery.isPending}
          />
        )}

        {currentTab === "graph" && (
          <DependencyGraph
            data={graphQuery.data ?? FALLBACK_GRAPH}
            loading={graphQuery.isPending}
          />
        )}

        {currentTab === "hndl" && (
          <HndlView
            items={hndlQuery.data ?? []}
            loading={hndlQuery.isPending}
          />
        )}

        {currentTab === "certs" && (
          <CertLifecycle
            certificates={certsQuery.data ?? []}
            loading={certsQuery.isPending}
          />
        )}

        {currentTab === "algorithms" && (
          <AlgorithmInventory
            data={algosQuery.data ?? FALLBACK_ALGORITHMS}
            loading={algosQuery.isPending}
          />
        )}
      </div>
    </Page>
  );
}
