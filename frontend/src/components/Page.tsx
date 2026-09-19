import type { ReactNode } from "react";

interface BreadcrumbSegment {
  label: string;
  /** If omitted, segment is the current (non-link) item. */
  href?: string;
}

interface PageProps {
  title: string;
  subtitle: string;
  action?: ReactNode;
  children: ReactNode;
  /** Breadcrumb trail — satisfying §4.7b. Rendered above the h1. */
  breadcrumbs?: BreadcrumbSegment[];
}

/**
 * Top-level page wrapper with breadcrumbs (§4.7b), h1 title, subtitle
 * and an optional action area (e.g. a "Launch scan" button).
 */
export function Page({ title, subtitle, action, children, breadcrumbs }: PageProps) {
  return (
    <div className="page">
      {breadcrumbs && breadcrumbs.length > 0 && (
        <nav aria-label="Breadcrumb" className="breadcrumb-nav">
          <ol>
            {breadcrumbs.map((crumb, index) =>
              crumb.href ? (
                <li key={index}>
                  <a href={crumb.href}>{crumb.label}</a>
                </li>
              ) : (
                <li key={index} aria-current="page">
                  {crumb.label}
                </li>
              ),
            )}
          </ol>
        </nav>
      )}
      <div className="page-heading">
        <div>
          <h1>{title}</h1>
          <p>{subtitle}</p>
        </div>
        {action && <div className="page-actions">{action}</div>}
      </div>
      {children}
    </div>
  );
}
