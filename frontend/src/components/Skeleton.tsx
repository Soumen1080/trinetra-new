/** Shimmer skeleton loader — satisfies §4.5c (skeleton loaders, never spinners on blank pages). */
export function Skeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="skeleton" aria-label="Loading" aria-busy="true">
      {Array.from({ length: rows }, (_, i) => (
        <i key={i} />
      ))}
    </div>
  );
}
