export type RiskBand = "p0" | "p1" | "p2" | "none";

export const riskCopy: Record<RiskBand, { label: string; icon: string; action: string }> = {
  p0: { label: "Critical", icon: "!", action: "Act now" },
  p1: { label: "High", icon: "▲", action: "Plan next" },
  p2: { label: "Moderate", icon: "●", action: "Track" },
  none: { label: "Not assessed", icon: "?", action: "Add context" },
};

export function riskBand(priority?: string | null): RiskBand {
  return priority === "p0" || priority === "p1" || priority === "p2" ? priority : "none";
}

export function titleCase(value?: string | null) {
  return value ? value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()) : "—";
}

export function formatDate(value?: string | null) {
  return value ? new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)) : "Not available";
}
