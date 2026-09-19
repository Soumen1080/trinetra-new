import type { ReactNode } from "react";
import { Link } from "react-router-dom";

interface TooltipProps {
  /** Short accessible label describing this tooltip's subject. */
  label: string;
  children: ReactNode;
  /** If set, a "Learn more" link to the glossary is appended. */
  glossaryTerm?: string;
}

/**
 * Inline ⓘ tooltip satisfying §4.3a — every acronym/term has a contextual
 * tooltip with an optional link to the Glossary page.
 */
export function Tooltip({ label, children, glossaryTerm }: TooltipProps) {
  return (
    <span className="tip">
      <button type="button" className="tip-button" aria-label={label}>
        ⓘ
      </button>
      <span role="tooltip">
        {children}
        {glossaryTerm && (
          <Link to={`/glossary#${encodeURIComponent(glossaryTerm.toLowerCase())}`} className="tip-glossary-link">
            Glossary ↗
          </Link>
        )}
      </span>
    </span>
  );
}
