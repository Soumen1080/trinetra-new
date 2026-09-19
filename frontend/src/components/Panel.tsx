import type { ReactNode } from "react";

interface PanelProps {
  title: string;
  /** Secondary subtitle / hint shown in muted text. Accepts ReactNode for inline tooltips. */
  note?: ReactNode;
  children: ReactNode;
  /** Optional action placed in the panel header (e.g. a link or button). */
  action?: ReactNode;
}

/**
 * Consistent panel frame used by every dashboard section, explorer results
 * area, and scan detail card — satisfying §4.8b (shared component library).
 */
export function Panel({ title, note, children, action }: PanelProps) {
  return (
    <section className="panel">
      <header>
        <div>
          <h2>{title}</h2>
          {note && <p>{note}</p>}
        </div>
        {action && <div className="panel-action">{action}</div>}
      </header>
      {children}
    </section>
  );
}
