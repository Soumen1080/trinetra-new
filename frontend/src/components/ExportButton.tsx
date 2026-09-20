import { useState } from "react";
import { useApi } from "../hooks/useApi";

interface ExportButtonProps {
  /** Current filter parameters to include in export */
  filters: Record<string, string | number | undefined | null>;
  /** Optional text override */
  label?: string;
}

/**
 * CSV export button for filtered artefact lists (§4.6, §4.8).
 * Downloads filtered results as CSV for offline analysis or CMDB import.
 */
export function ExportButton({ filters, label = "Export CSV" }: ExportButtonProps) {
  const api = useApi();
  const [exporting, setExporting] = useState(false);
  const [message, setMessage] = useState<string>();

  const handleExport = async () => {
    try {
      setExporting(true);
      setMessage(undefined);
      const { blob, name } = await api.exportArtefactsCsv(filters);
      
      // Trigger browser download
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = name;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      
      setMessage("Export downloaded successfully");
      setTimeout(() => setMessage(undefined), 3000);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Export failed");
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="export-button-wrapper">
      <button
        type="button"
        onClick={handleExport}
        disabled={exporting}
        className="export-button"
        aria-busy={exporting}
      >
        {exporting ? "Exporting…" : label} 📥
      </button>
      {message && (
        <p
          role="status"
          className={`export-message ${message.includes("fail") ? "error" : "success"}`}
        >
          {message}
        </p>
      )}
    </div>
  );
}
