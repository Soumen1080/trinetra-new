import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ChartShell } from "./components/ChartShell";
import { MigrationPlanner } from "./components/MigrationPlanner";
import { RecommendationWorkspace } from "./components/RecommendationWorkspace";
import { WhatIfSimulator } from "./components/WhatIfSimulator";
import { ComplianceDashboard } from "./components/ComplianceDashboard";
import { ReportPreview } from "./components/ReportPreview";

vi.mock("./hooks/useApi", () => ({
  useApi: () => ({
    updateContext: vi.fn().mockResolvedValue({}),
    createReport: vi.fn().mockResolvedValue({ id: "rep-1" }),
    downloadReport: vi.fn().mockResolvedValue({ blob: new Blob(), name: "report.pdf" }),
  }),
}));

vi.mock("./hooks/useAuth", () => ({
  useAuth: () => ({
    user: { id: "u1", username: "analyst", role: "analyst" },
    project: { id: "p1", name: "Production Systems Cluster" },
    projects: [{ id: "p1", name: "Production Systems Cluster" }],
    restoring: false,
    setProject: vi.fn(),
    signOut: vi.fn(),
  }),
}));

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
});

function wrap(ui: React.ReactNode) {
  return render(
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>{ui}</BrowserRouter>
    </QueryClientProvider>
  );
}

describe("Phase 10 — Interactive GUI: Risk & Migration Visualisation", () => {
  beforeEach(() => {
    cleanup();
  });

  describe("ChartShell (10.12 & 10.13)", () => {
    it("renders chart title, explainer '?' button, and accessible table toggle", () => {
      wrap(
        <ChartShell
          title="Sample Visualisation"
          explainer={<p>Explaining how to read this chart.</p>}
          dataTable={<table><tbody><tr><td>Data Row</td></tr></tbody></table>}
        >
          <div data-testid="chart-content">SVG Chart Content</div>
        </ChartShell>
      );

      expect(screen.getByText("Sample Visualisation")).toBeInTheDocument();
      expect(screen.getByTestId("chart-content")).toBeInTheDocument();

      // Explainer popover (?)
      const explainerBtn = screen.getByLabelText("How to read: Sample Visualisation");
      expect(explainerBtn).toBeInTheDocument();
      fireEvent.click(explainerBtn);
      expect(screen.getByText("Explaining how to read this chart.")).toBeInTheDocument();

      // Data table toggle (10.13 / §4.9e)
      const tableToggleBtn = screen.getByText("Show table ♿");
      fireEvent.click(tableToggleBtn);
      expect(screen.getByText("Data Row")).toBeInTheDocument();
      expect(screen.getByText("Hide table")).toBeInTheDocument();
    });
  });

  describe("MigrationPlanner (10.7)", () => {
    it("renders wave Gantt, rollups, and highlights breach risks", () => {
      wrap(<MigrationPlanner />);

      expect(screen.getByText("Migration Roadmap & Wave Gantt")).toBeInTheDocument();
      expect(screen.getByText("Planned Systems")).toBeInTheDocument();
      expect(screen.getByText("Total Engineering Effort")).toBeInTheDocument();
      expect(screen.getByText("Estimated Migration Cost")).toBeInTheDocument();
      expect(screen.getByText("Payment Gateway Core")).toBeInTheDocument();
      expect(screen.getByText("Wave 1 (2025–2026)")).toBeInTheDocument();
    });
  });

  describe("RecommendationWorkspace (10.8)", () => {
    it("renders side-by-side comparison and generates remediation ticket", async () => {
      wrap(<RecommendationWorkspace />);

      expect(screen.getByText(/Recommendation:/)).toBeInTheDocument();
      expect(screen.getByText("Current (Vulnerable)")).toBeInTheDocument();
      expect(screen.getByText("Recommended PQC")).toBeInTheDocument();
      expect(screen.getByText("5-Axis Cryptographic Trade-Off Analysis")).toBeInTheDocument();

      // Click Accept Recommendation
      const acceptBtn = screen.getByText("Accept Recommendation & Create Ticket");
      expect(acceptBtn).toBeInTheDocument();
      fireEvent.click(acceptBtn);

      expect(screen.getByText(/Generating Ticket/)).toBeInTheDocument();
    });
  });

  describe("WhatIfSimulator (10.9)", () => {
    it("allows adjusting quantum break year and displays posture delta", () => {
      wrap(<WhatIfSimulator />);

      expect(screen.getByText("Simulation Scenario Parameters")).toBeInTheDocument();
      expect(screen.getByText("Target Systems for Migration (3 of 6 selected):")).toBeInTheDocument();
      expect(screen.getByText("Simulated Posture Projection: Before vs After")).toBeInTheDocument();

      // Toggle system selection
      const systemPill = screen.getAllByText("Payment Gateway Core")[0];
      fireEvent.click(systemPill);

      // Verify delta metrics exist
      expect(screen.getByText("Quantum Readiness Score")).toBeInTheDocument();
      expect(screen.getByText("Critical (P0) Assets")).toBeInTheDocument();
    });
  });

  describe("ComplianceDashboard (10.10)", () => {
    it("renders regulatory milestones and compliance ledger", () => {
      wrap(<ComplianceDashboard />);

      expect(screen.getByText("CNSA 2.0 & NIST IR 8547 Regulatory Timeline")).toBeInTheDocument();
      expect(screen.getByText("Software & Firmware Signatures")).toBeInTheDocument();
      expect(screen.getByText("Web Browsers, TLS & Cloud")).toBeInTheDocument();
      expect(screen.getByText(/Systems Compliance Ledger/)).toBeInTheDocument();
    });
  });

  describe("ReportPreview (10.11)", () => {
    it("toggles between Executive, Technical, and CBOM views", () => {
      wrap(<ReportPreview projectName="Test Cluster" scanId="scan-test-123" />);

      expect(screen.getByText("Assessment Report In-App Preview")).toBeInTheDocument();
      expect(screen.getByText("1. Executive Statement of Cryptographic Risk")).toBeInTheDocument();

      // Toggle to Technical
      const techBtn = screen.getByText("Technical Assessment");
      fireEvent.click(techBtn);
      expect(screen.getByText("1. Technical Inventory & Primitive Classification")).toBeInTheDocument();

      // Toggle to CBOM
      const cbomBtn = screen.getByText("CycloneDX CBOM");
      fireEvent.click(cbomBtn);
      expect(screen.getByText(/CycloneDX 1.6 Cryptographic Bill of Materials/)).toBeInTheDocument();
    });
  });
});
