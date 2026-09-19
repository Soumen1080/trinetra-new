import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { Page } from "../components/Page";
import { MigrationPlanner } from "../components/MigrationPlanner";
import { RecommendationWorkspace } from "../components/RecommendationWorkspace";
import { WhatIfSimulator } from "../components/WhatIfSimulator";
import { ComplianceDashboard } from "../components/ComplianceDashboard";
import { ReportPreview } from "../components/ReportPreview";

const TABS = [
  { id: "planner", label: "Migration Roadmap", badge: "10.7" },
  { id: "recommendations", label: "Recommendations", badge: "10.8" },
  { id: "whatif", label: "What-If Simulator", badge: "10.9" },
  { id: "compliance", label: "Compliance Deadlines", badge: "10.10" },
  { id: "report", label: "Report Preview", badge: "10.11" },
] as const;

type TabId = typeof TABS[number]["id"];

export function MigrationPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const api = useApi();
  const { project } = useAuth();

  const currentTab = (searchParams.get("tab") as TabId) || "planner";

  const handleTabChange = (tabId: TabId) => {
    setSearchParams({ tab: tabId });
  };

  // Optional query for compliance data
  const complianceQuery = useQuery({
    queryKey: ["compliance", project?.id],
    queryFn: async () => {
      try {
        return await api.compliance();
      } catch {
        return undefined;
      }
    },
  });

  return (
    <Page
      title="PQC Migration & Remediation"
      subtitle="Engineering roadmaps, side-by-side NIST recommendations, posture simulations, and CNSA 2.0 tracking."
      breadcrumbs={[
        { label: "Overview", href: "/" },
        { label: "Migration Planning" },
      ]}
    >
      {/* Tab Navigation (§4.7b, 10.14) */}
      <nav className="vis-tab-bar" aria-label="Migration Planning Views">
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
        {currentTab === "planner" && <MigrationPlanner />}

        {currentTab === "recommendations" && <RecommendationWorkspace />}

        {currentTab === "whatif" && <WhatIfSimulator />}

        {currentTab === "compliance" && (
          <ComplianceDashboard
            data={complianceQuery.data}
            loading={complianceQuery.isPending}
          />
        )}

        {currentTab === "report" && (
          <ReportPreview
            projectName={project?.name ?? "Production Systems Cluster"}
          />
        )}
      </div>
    </Page>
  );
}
