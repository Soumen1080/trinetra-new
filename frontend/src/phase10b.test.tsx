import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import axe from "axe-core";
import { GuidedTour } from "./components/GuidedTour";
import { AccessibilityMenu } from "./components/AccessibilityMenu";
import { DemoDataLoader, DEMO_DATASET_KEY, DEMO_DASHBOARD } from "./components/DemoDataLoader";
import { PersonaSwitcher } from "./components/PersonaSwitcher";
import { RiskBadge } from "./components/RiskBadge";
import { ChartShell } from "./components/ChartShell";
import { ArtefactTable } from "./components/ArtefactTable";
import { ArtefactDrawer } from "./components/ArtefactDrawer";
import { RecommendationWorkspace } from "./components/RecommendationWorkspace";
import { riskCopy, titleCase } from "./risk";
import type { Artefact } from "./api/client";

vi.mock("./hooks/useApi", () => ({
  useApi: () => ({
    artefact: vi.fn().mockResolvedValue({
      artefact: {
        id: "art-test-01",
        name: "Payment Gateway TLS Key Exchange",
        type: "algorithm",
        algorithm: "RSA-2048",
        priority: "p0",
        risk_score: 94.2,
        discovered_by: "source_scanner",
        location: "src/crypto/tls_handler.py:42",
        recommendation: "Migrate to ML-KEM-768 (FIPS 203) hybrid key exchange",
      },
      evidence: [
        {
          location: "src/crypto/tls_handler.py:42",
          snippet: "ctx.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384')",
          confidence: "HIGH",
          detector: "ast_crypto_detector",
        },
      ],
    }),
    risk: vi.fn().mockResolvedValue({
      assessment: {
        mosca: {
          x_years: 10,
          y_years: 8,
          z_years: 3,
          migration_deadline_year: 2029,
          breach: true,
        },
      },
    }),
  }),
}));

vi.mock("./hooks/useAuth", () => ({
  useAuth: () => ({
    user: { id: "u1", username: "analyst", role: "analyst" },
    project: { id: "p1", name: "Production Systems Cluster" },
    projects: [{ id: "p1", name: "Production Systems Cluster" }],
  }),
}));

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
}

function wrap(ui: React.ReactNode, client = createTestQueryClient()) {
  return render(
    <QueryClientProvider client={client}>
      <BrowserRouter>{ui}</BrowserRouter>
    </QueryClientProvider>
  );
}

describe("Phase 10B — Usability Validation & Accessibility (R21)", () => {
  beforeEach(() => {
    cleanup();
    localStorage.clear();
    document.documentElement.dataset.colorblind = "normal";
    document.documentElement.dataset.reducedMotion = "false";
    document.documentElement.dataset.highContrast = "false";
  });

  /* ──────────────────────────────────────────────────────────────────────────
   * 10B.3 — Guided Product Tour (§4.11a)
   * ────────────────────────────────────────────────────────────────────────── */
  describe("10B.3 — Guided Product Tour (§4.11a)", () => {
    it("renders step 1 for Executive / CISO persona and navigates steps", () => {
      wrap(<GuidedTour isOpen={true} />);

      expect(screen.getByRole("dialog", { name: /guided product tour/i })).toBeInTheDocument();
      expect(screen.getByText(/step 1 of 4/i)).toBeInTheDocument();
      expect(screen.getByText(/primary: executive \/ ciso/i)).toBeInTheDocument();
      expect(screen.getByText("Executive Readiness Overview")).toBeInTheDocument();

      // Advance to step 2
      const nextBtn = screen.getByRole("button", { name: /next screen →/i });
      fireEvent.click(nextBtn);

      expect(screen.getByText(/step 2 of 4/i)).toBeInTheDocument();
      expect(screen.getByText("CBOM Explorer & Evidence Drawer")).toBeInTheDocument();
      expect(screen.getByText(/primary: security analyst/i)).toBeInTheDocument();
    });

    it("can be skipped and records completion in localStorage", () => {
      const onClose = vi.fn();
      wrap(<GuidedTour isOpen={true} onClose={onClose} />);

      const skipBtn = screen.getByRole("button", { name: /skip tour/i });
      fireEvent.click(skipBtn);

      expect(localStorage.getItem("trinetra_tour_completed")).toBe("true");
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it("dismisses on Escape key (§4.9c)", () => {
      const onClose = vi.fn();
      wrap(<GuidedTour isOpen={true} onClose={onClose} />);

      fireEvent.keyDown(window, { key: "Escape" });
      expect(onClose).toHaveBeenCalled();
    });
  });

  /* ──────────────────────────────────────────────────────────────────────────
   * 10B.4 — One-Click Demo Dataset Loader (§4.11b)
   * ────────────────────────────────────────────────────────────────────────── */
  describe("10B.4 — One-Click Demo Dataset Loader (§4.11b)", () => {
    it("loads demo dataset into query cache and renders active status", async () => {
      const client = createTestQueryClient();
      wrap(<DemoDataLoader />, client);

      const loadBtn = screen.getByRole("button", { name: /load demo dataset/i });
      fireEvent.click(loadBtn);

      await vi.waitFor(() => {
        expect(screen.getByText(/demo dataset active/i)).toBeInTheDocument();
      });

      expect(localStorage.getItem(DEMO_DATASET_KEY)).toBe("true");
      const cachedDashboard = client.getQueryData(["dashboard"]);
      expect(cachedDashboard).toEqual(DEMO_DASHBOARD);
    });
  });

  /* ──────────────────────────────────────────────────────────────────────────
   * 10B.5 — Automated Accessibility Audit (axe-core) & Keyboard Navigation (§4.9)
   * ────────────────────────────────────────────────────────────────────────── */
  describe("10B.5 — Accessibility Audit (§4.9)", () => {
    it("passes axe-core automated audit on core interactive components", async () => {
      const { container } = wrap(
        <div>
          <PersonaSwitcher />
          <RiskBadge priority="p0" />
          <ChartShell
            title="Posture Trend"
            explainer={<p>Explains posture movement over time.</p>}
            dataTable={<table><tbody><tr><td>2026-01</td><td>82</td></tr></tbody></table>}
          >
            <div data-testid="chart-content">Chart Visual</div>
          </ChartShell>
        </div>
      );

      // Run axe on container excluding color-contrast (which needs full CSSOM/layout engine)
      const results = await axe.run(container, {
        rules: {
          "color-contrast": { enabled: false },
        },
      });

      expect(results.violations).toEqual([]);
    });

    it("provides accessible data table toggle on visualisations (§4.9e)", () => {
      wrap(
        <ChartShell
          title="Mosca Timeline Distribution"
          explainer={<p>How to read Mosca timeline.</p>}
          dataTable={<table aria-label="Mosca tabular data"><tbody><tr><td>Payment</td><td>2029</td></tr></tbody></table>}
        >
          <div>Visual Chart</div>
        </ChartShell>
      );

      const toggleBtn = screen.getByRole("button", { name: /show table ♿/i });
      expect(toggleBtn).toBeInTheDocument();
      expect(toggleBtn).toHaveAttribute("aria-expanded", "false");

      fireEvent.click(toggleBtn);
      expect(toggleBtn).toHaveAttribute("aria-expanded", "true");
      expect(screen.getByRole("table", { name: /mosca tabular data/i })).toBeInTheDocument();
    });

    it("allows dismissing ArtefactDrawer with Escape key (§4.9c)", async () => {
      const closeFn = vi.fn();
      wrap(<ArtefactDrawer artefactId="art-test-01" close={closeFn} />);

      await vi.waitFor(() => {
        expect(screen.getByRole("dialog", { name: /payment gateway tls key exchange detail/i })).toBeInTheDocument();
      });

      const drawer = screen.getByRole("dialog");
      fireEvent.keyDown(drawer, { key: "Escape" });
      expect(closeFn).toHaveBeenCalled();
    });
  });

  /* ──────────────────────────────────────────────────────────────────────────
   * 10B.6 — Colour-Blind Simulation & Triple Redundancy (§4.9b)
   * ────────────────────────────────────────────────────────────────────────── */
  describe("10B.6 — Colour-Blind Simulation & Triple Redundancy (§4.9b)", () => {
    it("satisfies triple-redundancy on every risk band (color + text + icon)", () => {
      const bands: Array<"p0" | "p1" | "p2" | "none"> = ["p0", "p1", "p2", "none"];

      for (const band of bands) {
        cleanup();
        wrap(<RiskBadge priority={band} />);

        const copy = riskCopy[band];
        const badge = screen.getByLabelText(`${copy.label}: ${copy.action}`);

        // 1. Curated color class
        expect(badge).toHaveClass(`risk-${band}`);
        // 2. Clear text label
        expect(badge).toHaveTextContent(copy.label);
        // 3. Geometric icon
        expect(badge.querySelector(".risk-icon")).toHaveTextContent(copy.icon);
      }
    });

    it("applies colour-vision deficiency filter modes to DOM dataset", () => {
      wrap(<AccessibilityMenu />);

      const trigger = screen.getByRole("button", { name: /accessibility settings/i });
      fireEvent.click(trigger);

      const select = screen.getByLabelText(/colour-vision deficiency filter/i);

      // Deuteranopia (green-blind)
      fireEvent.change(select, { target: { value: "deuteranopia" } });
      expect(document.documentElement.dataset.colorblind).toBe("deuteranopia");

      // Protanopia (red-blind)
      fireEvent.change(select, { target: { value: "protanopia" } });
      expect(document.documentElement.dataset.colorblind).toBe("protanopia");

      // Tritanopia (blue-blind)
      fireEvent.change(select, { target: { value: "tritanopia" } });
      expect(document.documentElement.dataset.colorblind).toBe("tritanopia");

      // Achromatopsia (monochrome / grayscale)
      fireEvent.change(select, { target: { value: "achromatopsia" } });
      expect(document.documentElement.dataset.colorblind).toBe("achromatopsia");
    });
  });

  /* ──────────────────────────────────────────────────────────────────────────
   * 10B.1 & 10B.2 — 5-Persona Usability Testing Tasks
   * ────────────────────────────────────────────────────────────────────────── */
  describe("10B.1 & 10B.2 — Usability Task Verification (Tasks A, B, C)", () => {
    it("Task A (Find & Explain): Surfaces riskiest finding with plain-English summary", async () => {
      wrap(<ArtefactDrawer artefactId="art-test-01" close={vi.fn()} />);

      await vi.waitFor(() => {
        expect(screen.getByText("Payment Gateway TLS Key Exchange")).toBeInTheDocument();
      });

      // Verification of plain-English summary before any jargon (§4.3b)
      const summary = screen.getByText(/RSA-2048/i);
      expect(summary).toBeInTheDocument();
      expect(screen.getByText(/Act now/i)).toBeInTheDocument();
      expect(screen.getByText(/94.2 \/ 100/i)).toBeInTheDocument();
    });

    it("Task B (Remediation): Surfaces replacement algorithm and radar trade-offs", async () => {
      wrap(<RecommendationWorkspace />);

      expect(screen.getByText(/Recommendation: Payment Core TLS 1.3 Key Exchange/i)).toBeInTheDocument();
      expect(screen.getAllByText(/ML-KEM-768/i).length).toBeGreaterThan(0);
      expect(screen.getAllByText(/NIST FIPS 203/i).length).toBeGreaterThan(0);

      // Ticket generation action (§4.4a)
      const ticketBtn = screen.getByRole("button", { name: /accept recommendation & create ticket/i });
      expect(ticketBtn).toBeInTheDocument();
      fireEvent.click(ticketBtn);

      await vi.waitFor(() => {
        expect(screen.getByText(/ticket.*created/i)).toBeInTheDocument();
      });
    });

    it("Task C (Verification): Displays code evidence at file:line and Mosca arithmetic", async () => {
      wrap(<ArtefactDrawer artefactId="art-test-01" close={vi.fn()} />);

      await vi.waitFor(() => {
        expect(screen.getAllByText(/src\/crypto\/tls_handler\.py:42/i).length).toBeGreaterThan(0);
      });

      // Code snippet
      expect(screen.getByText(/ctx\.set_ciphers/i)).toBeInTheDocument();

      // Mosca timing parameters
      expect(screen.getByText(/X — data life/i)).toBeInTheDocument();
      expect(screen.getByText("10 yr")).toBeInTheDocument();
      expect(screen.getByText(/Y — quantum break/i)).toBeInTheDocument();
      expect(screen.getByText("8 yr")).toBeInTheDocument();
      expect(screen.getByText(/Z — migration/i)).toBeInTheDocument();
      expect(screen.getByText("3 yr")).toBeInTheDocument();
      expect(screen.getByText(/Deadline \(Y − Z\)/i)).toBeInTheDocument();
      expect(screen.getByText("2029")).toBeInTheDocument();
    });
  });

  /* ──────────────────────────────────────────────────────────────────────────
   * 10B.8 — Plain-Language Sweep (§4.3)
   * ────────────────────────────────────────────────────────────────────────── */
  describe("10B.8 — Plain-Language Sweep & Zero Raw Enums (§4.3)", () => {
    it("transforms snake_case and database enums into human title case", () => {
      expect(titleCase("hardware_module")).toBe("Hardware Module");
      expect(titleCase("cloud_service")).toBe("Cloud Service");
      expect(titleCase("related_material")).toBe("Related Material");
      expect(titleCase("source_scanner")).toBe("Source Scanner");
      expect(titleCase(null)).toBe("—");
    });
  });

  /* ──────────────────────────────────────────────────────────────────────────
   * 10B.9 — 100k-Row Virtualisation Benchmark (§4.10)
   * ────────────────────────────────────────────────────────────────────────── */
  describe("10B.9 — 100k-Row Virtualisation Benchmark (§4.10)", () => {
    it("virtualises 100,000 artefacts without exhausting DOM nodes", () => {
      // Generate synthetic 100k artefact headers
      const sample100k: Artefact[] = Array.from({ length: 100_000 }, (_, i) => ({
        id: `art-${i}`,
        project_id: "p1",
        scan_id: "s1",
        name: `Crypto Asset ${i}`,
        type: i % 2 === 0 ? "algorithm" : "key",
        algorithm: i % 2 === 0 ? "RSA-2048" : "AES-256",
        priority: i % 10 === 0 ? "p0" : "p2",
        discovered_by: "source_scanner",
        quantum_vulnerability: i % 2 === 0 ? "vulnerable" : "safe",
      }));

      const { container } = wrap(<ArtefactTable rows={sample100k} virtualized={true} />);

      // Verify that DOM does not contain 100k nodes (TanStack Virtual maintains a small window)
      const renderedRows = container.querySelectorAll(".table-row");
      expect(renderedRows.length).toBeLessThan(100);
      expect(container.querySelector(".artefact-table.virtual")).toBeInTheDocument();
    });
  });

  /* ──────────────────────────────────────────────────────────────────────────
   * §4.1b — Persona Switcher
   * ────────────────────────────────────────────────────────────────────────── */
  describe("§4.1b — Persona Switcher", () => {
    it("renders persona options and switches active persona", () => {
      wrap(<PersonaSwitcher />);

      const select = screen.getByRole("combobox", { name: /active role persona/i });
      expect(select).toBeInTheDocument();

      fireEvent.change(select, { target: { value: "ciso" } });
      expect(localStorage.getItem("trinetra_active_persona")).toBe("ciso");

      fireEvent.change(select, { target: { value: "developer" } });
      expect(localStorage.getItem("trinetra_active_persona")).toBe("developer");
    });
  });
});
