import { riskBand, riskCopy } from "../risk";

/**
 * Renders a risk priority badge following §4.3d:
 * colour + text label + icon — never colour alone.
 */
export function RiskBadge({ priority }: { priority?: string | null }) {
  const band = riskBand(priority);
  const copy = riskCopy[band];
  return (
    <span className={`risk risk-${band}`} aria-label={`${copy.label}: ${copy.action}`}>
      <b aria-hidden="true" className="risk-icon">
        {copy.icon}
      </b>
      {copy.label}
    </span>
  );
}
