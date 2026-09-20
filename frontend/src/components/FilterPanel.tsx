import { ReactNode } from "react";

export interface FilterOption {
  value: string;
  label: string;
  count?: number;
  icon?: ReactNode;
}

interface FilterGroupProps {
  label: string;
  options: FilterOption[];
  selected: string | string[];
  onChange: (value: string) => void;
  multi?: boolean;
  renderOption?: (option: FilterOption) => ReactNode;
}

/**
 * Filter group component (§4.1, §4.2).
 * Displays faceted filters with live result counts.
 */
export function FilterGroup({
  label,
  options,
  selected,
  onChange,
  multi = false,
  renderOption,
}: FilterGroupProps) {
  const isSelected = (value: string) =>
    Array.isArray(selected) ? selected.includes(value) : selected === value;

  const handleToggle = (value: string) => {
    if (!multi) {
      onChange(isSelected(value) ? "" : value);
      return;
    }

    // Multi-select: toggle value in array
    const current = Array.isArray(selected) ? selected : selected ? [selected] : [];
    const next = isSelected(value)
      ? current.filter((v) => v !== value)
      : [...current, value];
    onChange(next.join(","));
  };

  if (!options.length) {
    return (
      <fieldset className="filter-group filter-group-empty">
        <legend>{label}</legend>
        <p className="muted">Filters appear once results load.</p>
      </fieldset>
    );
  }

  return (
    <fieldset className="filter-group">
      <legend>{label}</legend>
      <div className="filter-options">
        {options.map((option) => (
          <label key={option.value} className="filter-option">
            <input
              type={multi ? "checkbox" : "radio"}
              checked={isSelected(option.value)}
              onChange={() => handleToggle(option.value)}
              name={multi ? undefined : `filter-${label}`}
            />
            <span className="filter-option-label">
              {renderOption ? renderOption(option) : option.label}
              {option.count !== undefined && (
                <small className="filter-count">{option.count.toLocaleString()}</small>
              )}
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

interface FilterPanelProps {
  children: ReactNode;
  onReset?: () => void;
  hasActiveFilters?: boolean;
}

/**
 * Filter panel container (§4.2, §4.7c).
 * Provides consistent layout and reset functionality.
 */
export function FilterPanel({ children, onReset, hasActiveFilters }: FilterPanelProps) {
  return (
    <aside className="filter-panel" aria-label="Filters">
      {children}
      {hasActiveFilters && onReset && (
        <button type="button" onClick={onReset} className="filter-reset">
          Clear all filters
        </button>
      )}
    </aside>
  );
}
