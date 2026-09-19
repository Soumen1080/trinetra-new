import type { ReactNode } from "react";

interface EmptyProps {
  title: string;
  children: ReactNode;
  /** Primary CTA satisfying §4.4d — empty states teach rather than apologise. */
  action?: ReactNode;
  icon?: string;
}

/**
 * Teaching empty state: explains why there's nothing here and offers
 * an action to remedy it — never a blank page (§4.4d).
 */
export function Empty({ title, children, action, icon = "⌁" }: EmptyProps) {
  return (
    <section className="empty">
      <div aria-hidden="true" className="empty-mark">
        {icon}
      </div>
      <h2>{title}</h2>
      <p>{children}</p>
      {action}
    </section>
  );
}
