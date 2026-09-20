import { useState, useEffect, useRef } from "react";

interface SearchBarProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  debounceMs?: number;
  autoFocus?: boolean;
  /** Keyboard shortcut hint (e.g., "/" or "Ctrl+K") */
  shortcut?: string;
}

/**
 * Debounced search bar with keyboard shortcut support (§4.7e).
 * Implements instant search feel (<200ms perceived latency, §4.10b).
 */
export function SearchBar({
  value,
  onChange,
  placeholder = "Search…",
  debounceMs = 300,
  autoFocus = false,
  shortcut,
}: SearchBarProps) {
  const [localValue, setLocalValue] = useState(value);
  const inputRef = useRef<HTMLInputElement>(null);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Sync external value changes (e.g., from URL params)
  useEffect(() => {
    setLocalValue(value);
  }, [value]);

  // Debounced onChange
  useEffect(() => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    timeoutRef.current = setTimeout(() => {
      if (localValue !== value) {
        onChange(localValue);
      }
    }, debounceMs);

    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, [localValue, debounceMs, onChange, value]);

  // Global keyboard shortcut (e.g., "/" focuses search)
  useEffect(() => {
    if (!shortcut) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      // Focus search when shortcut pressed
      if (event.key === shortcut && !event.ctrlKey && !event.metaKey) {
        // Only if not typing in another input
        if (
          document.activeElement?.tagName !== "INPUT" &&
          document.activeElement?.tagName !== "TEXTAREA"
        ) {
          event.preventDefault();
          inputRef.current?.focus();
        }
      }

      // Escape clears and blurs
      if (event.key === "Escape" && document.activeElement === inputRef.current) {
        setLocalValue("");
        onChange("");
        inputRef.current?.blur();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [shortcut, onChange]);

  const handleClear = () => {
    setLocalValue("");
    onChange("");
    inputRef.current?.focus();
  };

  return (
    <div className="search-bar">
      <label htmlFor="search-input" className="search-label">
        <span className="visually-hidden">Search</span>
        <span className="search-icon" aria-hidden="true">
          🔍
        </span>
      </label>
      <input
        ref={inputRef}
        id="search-input"
        type="search"
        value={localValue}
        onChange={(e) => setLocalValue(e.target.value)}
        placeholder={placeholder}
        autoFocus={autoFocus}
        className="search-input"
        aria-label={placeholder}
      />
      {localValue && (
        <button
          type="button"
          onClick={handleClear}
          className="search-clear"
          aria-label="Clear search"
        >
          ×
        </button>
      )}
      {shortcut && !localValue && (
        <kbd className="search-shortcut" aria-hidden="true">
          {shortcut}
        </kbd>
      )}
    </div>
  );
}
