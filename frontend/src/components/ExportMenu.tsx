import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useApi } from "../hooks/useApi";
import { problem } from "./ErrorState";

/** All supported export formats with plain-English descriptions (§4.3 — no unexplained jargon). */
const FORMATS = [
  ["cyclonedx", "CBOM (CycloneDX 1.6)", "Machine-readable cryptographic inventory — the OWASP standard format."],
  ["spdx", "SPDX", "Software Bill of Materials format, compatible with existing supply-chain tooling."],
  ["json", "Native JSON", "Trinetra's complete structured result, including all assessments and evidence."],
  ["csv", "CSV spreadsheet", "Flat finding list — open in Excel or import into a CMDB."],
  ["xlsx", "Excel workbook", "Formatted multi-sheet workbook for offline analysis."],
  ["sarif", "SARIF", "Static-analysis results — upload to GitHub Code Scanning or Azure DevOps."],
  ["pdf-executive", "Executive PDF", "Plain-language posture summary for non-technical stakeholders."],
  ["pdf-technical", "Technical PDF", "Full detailed evidence and assessment report for security engineers."],
  ["html-technical", "Technical HTML", "Browsable self-contained technical report."],
] as const;

interface ExportMenuProps {
  scanId: string;
}

/**
 * Export menu with format descriptions in plain English (§4.3, §9.8).
 * Uses a <details> element so it degrades without JS.
 */
export function ExportMenu({ scanId }: ExportMenuProps) {
  const api = useApi();
  const [message, setMessage] = useState<string>();

  const exportReport = useMutation({
    mutationFn: async (format: string) => {
      const report = await api.createReport(scanId, format);
      return api.downloadReport(report.id);
    },
    onSuccess: ({ blob, name }) => {
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = name;
      link.click();
      URL.revokeObjectURL(url);
      setMessage("Your export has downloaded.");
    },
    onError: (error) => setMessage(problem(error)),
  });

  return (
    <details className="export-menu">
      <summary>Export ↓</summary>
      <div className="export-dropdown">
        <p className="export-hint">
          Choose a format. Each file is generated fresh from the current scan data.
        </p>
        {FORMATS.map(([format, label, note]) => (
          <button
            key={format}
            onClick={() => exportReport.mutate(format)}
            disabled={exportReport.isPending}
            className="export-option"
          >
            <b>{label}</b>
            <small>{note}</small>
          </button>
        ))}
        {message && (
          <p role="status" className="export-status">
            {message}
          </p>
        )}
      </div>
    </details>
  );
}
