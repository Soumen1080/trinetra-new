import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { Artefact, Scan, Dashboard } from "../api/client";

export const DEMO_DATASET_KEY = "trinetra_demo_dataset_active";

export const DEMO_DASHBOARD: Dashboard = {
  scan_count: 3,
  total_artefacts: 48,
  quantum_vulnerable_count: 34,
  quantum_safe_percent: 29,
  nearest_mosca_deadline_year: 2028,
  priority_counts: {
    p0: 18,
    p1: 16,
    p2: 8,
    none: 6,
  },
  needs_context_count: 2,
  artefact_type_counts: {
    algorithm: 22,
    certificate: 11,
    library: 9,
    key: 4,
    cloud_service: 2,
  },
  top_applications: [
    { id: "app-payment", name: "Payment Gateway Core", at_risk_count: 14 },
    { id: "app-auth", name: "Customer Identity & Auth", at_risk_count: 12 },
    { id: "app-edge", name: "Public Edge Ingress (TLS)", at_risk_count: 9 },
    { id: "app-archive", name: "Document Archive & Records", at_risk_count: 8 },
    { id: "app-b2b", name: "B2B API Dispatcher", at_risk_count: 5 },
  ],
  worst_offenders: [
    {
      id: "demo-art-1",
      scan_id: "demo-scan-3",
      name: "RSA-2048 Key Exchange (TLS 1.2)",
      type: "algorithm",
      algorithm: "RSA-2048",
      location: "src/crypto/tls_config.go:42",
      priority: "p0",
      risk_score: 92,
      discovered_by: "source",
      application_id: "app-payment",
      quantum_vulnerability: "shor_broken",
      recommendation: "Migrate to ML-KEM-768 hybrid key exchange (FIPS 203)",
    },
    {
      id: "demo-art-2",
      scan_id: "demo-scan-3",
      name: "ECDH P-256 Session Key Negotiation",
      type: "algorithm",
      algorithm: "ECDH-P256",
      location: "auth/session_manager.py:88",
      priority: "p0",
      risk_score: 88,
      discovered_by: "source",
      application_id: "app-auth",
      quantum_vulnerability: "shor_broken",
      recommendation: "Replace with X25519MLKEM768 hybrid KEX",
    },
    {
      id: "demo-art-3",
      scan_id: "demo-scan-3",
      name: "Legacy Triple-DES Encrypted Store",
      type: "algorithm",
      algorithm: "3DES",
      location: "db/legacy_cipher.java:114",
      priority: "p0",
      risk_score: 84,
      discovered_by: "source",
      application_id: "app-archive",
      quantum_vulnerability: "grover_weakened",
      recommendation: "Re-encrypt data at rest using AES-256-GCM",
    },
    {
      id: "demo-art-4",
      scan_id: "demo-scan-1",
      name: "AWS KMS Customer Key (RSA-3072)",
      type: "cloud_service",
      algorithm: "RSA-3072",
      location: "arn:aws:kms:us-east-1:123456789012:key/c039-4d8",
      priority: "p1",
      risk_score: 68,
      discovered_by: "cloud_hsm",
      application_id: "app-payment",
      quantum_vulnerability: "shor_broken",
      recommendation: "Plan AWS KMS PQC key migration wave",
    },
    {
      id: "demo-art-5",
      scan_id: "demo-scan-2",
      name: "GlobalSign Root CA Certificate",
      type: "certificate",
      algorithm: "SHA256withRSA-4096",
      location: "/etc/ssl/certs/internal-ca.pem:1",
      priority: "p1",
      risk_score: 62,
      discovered_by: "container",
      application_id: "app-edge",
      quantum_vulnerability: "shor_broken",
      recommendation: "Issue dual-root certificates with ML-DSA-65",
    },
  ],
  trend: [
    { scan_id: "demo-scan-1", created_at: "2026-08-01T10:00:00Z", artefact_count: 54, critical_count: 24 },
    { scan_id: "demo-scan-2", created_at: "2026-08-15T14:30:00Z", artefact_count: 51, critical_count: 21 },
    { scan_id: "demo-scan-3", created_at: "2026-09-01T09:15:00Z", artefact_count: 48, critical_count: 18 },
  ],
};

export const DEMO_SCANS: Scan[] = [
  {
    id: "demo-scan-3",
    target_kind: "git_repository",
    target_identifier: "https://github.com/enterprise/core-payment-gateway",
    display_name: "Core Payment & Ingress Services",
    status: "succeeded",
    created_at: "2026-09-01T09:15:00Z",
    finished_at: "2026-09-01T09:18:42Z",
    updated_at: "2026-09-01T09:18:42Z",
    artefact_count: 48,
  },
  {
    id: "demo-scan-2",
    target_kind: "container_image",
    target_identifier: "docker.internal/auth-gateway:v2.4.0",
    display_name: "Customer Auth Gateway Container",
    status: "succeeded",
    created_at: "2026-08-15T14:30:00Z",
    finished_at: "2026-08-15T14:32:10Z",
    updated_at: "2026-08-15T14:32:10Z",
    artefact_count: 51,
  },
  {
    id: "demo-scan-1",
    target_kind: "cloud_account",
    target_identifier: "aws:us-east-1:123456789012",
    display_name: "Production AWS KMS & PKCS#11 HSM",
    status: "succeeded",
    created_at: "2026-08-01T10:00:00Z",
    finished_at: "2026-08-01T10:01:25Z",
    updated_at: "2026-08-01T10:01:25Z",
    artefact_count: 54,
  },
];

interface DemoDataLoaderProps {
  buttonLabel?: string;
  className?: string;
  variant?: "primary" | "secondary" | "quiet";
}

export function DemoDataLoader({
  buttonLabel = "⚡ Load Demo Dataset",
  className = "",
  variant = "secondary",
}: DemoDataLoaderProps) {
  const queryClient = useQueryClient();
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(() => {
    return localStorage.getItem(DEMO_DATASET_KEY) === "true";
  });

  const handleLoadDemoData = () => {
    setLoading(true);

    // Populate TanStack Query cache with comprehensive demo dataset
    setTimeout(() => {
      // Seed dashboard query
      queryClient.setQueryData(["dashboard"], DEMO_DASHBOARD);
      queryClient.setQueriesData({ queryKey: ["dashboard"] }, DEMO_DASHBOARD);

      // Seed scans query
      const scansData = {
        items: DEMO_SCANS,
        total: DEMO_SCANS.length,
        offset: 0,
        limit: 25,
      };
      queryClient.setQueryData(["scans"], scansData);
      queryClient.setQueriesData({ queryKey: ["scans"] }, scansData);

      // Seed artefacts queries
      const artefactsData = {
        items: DEMO_DASHBOARD.worst_offenders,
        total: 48,
        offset: 0,
        limit: 50,
        facets: {
          type: { algorithm: 22, certificate: 11, library: 9, key: 4, cloud_service: 2 },
          priority: { p0: 18, p1: 16, p2: 8, none: 6 },
          application: {
            "app-payment": 14,
            "app-auth": 12,
            "app-edge": 9,
            "app-archive": 8,
            "app-b2b": 5,
          },
          algorithm: { "RSA-2048": 12, "ECDH-P256": 8, "AES-256-GCM": 14, "3DES": 4, "ML-KEM-768": 6 },
          quantum_status: { shor_broken: 30, grover_weakened: 4, quantum_safe: 14 },
          scanner: { source: 32, container: 10, cloud_hsm: 6 },
        },
      };
      queryClient.setQueryData(["artefacts"], artefactsData);
      queryClient.setQueriesData({ queryKey: ["artefacts"] }, artefactsData);

      localStorage.setItem(DEMO_DATASET_KEY, "true");
      setLoaded(true);
      setLoading(false);
    }, 50);
  };

  const handleResetDemoData = () => {
    localStorage.removeItem(DEMO_DATASET_KEY);
    setLoaded(false);
    queryClient.invalidateQueries();
  };

  return (
    <div className={`demo-data-loader ${className}`}>
      {!loaded ? (
        <button
          type="button"
          className={`button ${variant}`}
          onClick={handleLoadDemoData}
          disabled={loading}
          aria-label="Load demo dataset with 48 cryptographic findings and 6 applications (§4.11b)"
          title="Populate the workspace instantly with a realistic enterprise crypto inventory (§4.11b)"
        >
          {loading ? "Loading demo dataset…" : buttonLabel}
        </button>
      ) : (
        <div className="demo-loaded-badge">
          <span className="demo-badge-indicator">✓ Demo Dataset Active (48 findings)</span>
          <button
            type="button"
            className="button quiet small demo-reset-btn"
            onClick={handleResetDemoData}
            title="Reset demo data and restore live database view"
            aria-label="Reset demo dataset"
          >
            Reset
          </button>
        </div>
      )}
    </div>
  );
}
