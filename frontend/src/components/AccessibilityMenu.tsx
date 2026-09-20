import { useState, useEffect } from "react";

export type ColorBlindMode = "normal" | "protanopia" | "deuteranopia" | "tritanopia" | "achromatopsia";

const STORAGE_KEY_CB = "trinetra_a11y_colorblind";
const STORAGE_KEY_RM = "trinetra_a11y_reduced_motion";
const STORAGE_KEY_HC = "trinetra_a11y_high_contrast";

export function AccessibilityMenu() {
  const [isOpen, setIsOpen] = useState(false);
  const [colorBlindMode, setColorBlindMode] = useState<ColorBlindMode>(() => {
    return (localStorage.getItem(STORAGE_KEY_CB) as ColorBlindMode) || "normal";
  });
  const [reducedMotion, setReducedMotion] = useState<boolean>(() => {
    return localStorage.getItem(STORAGE_KEY_RM) === "true";
  });
  const [highContrast, setHighContrast] = useState<boolean>(() => {
    return localStorage.getItem(STORAGE_KEY_HC) === "true";
  });

  // Apply color-blind mode to html/body
  useEffect(() => {
    document.documentElement.dataset.colorblind = colorBlindMode;
    localStorage.setItem(STORAGE_KEY_CB, colorBlindMode);
  }, [colorBlindMode]);

  // Apply reduced motion
  useEffect(() => {
    document.documentElement.dataset.reducedMotion = String(reducedMotion);
    localStorage.setItem(STORAGE_KEY_RM, String(reducedMotion));
  }, [reducedMotion]);

  // Apply high contrast
  useEffect(() => {
    document.documentElement.dataset.highContrast = String(highContrast);
    localStorage.setItem(STORAGE_KEY_HC, String(highContrast));
  }, [highContrast]);

  return (
    <div className="a11y-menu-container">
      <button
        type="button"
        className="button quiet a11y-trigger-btn"
        onClick={() => setIsOpen((prev) => !prev)}
        aria-expanded={isOpen}
        aria-haspopup="dialog"
        aria-label="Accessibility settings and color-blind simulator"
        title="Accessibility & Color-Vision Simulator (§4.9)"
      >
        <span aria-hidden="true">♿</span>
        <span>A11y</span>
        {colorBlindMode !== "normal" && <span className="a11y-active-indicator" title="Filter active">•</span>}
      </button>

      {isOpen && (
        <div
          className="a11y-modal"
          role="dialog"
          aria-label="Accessibility & Vision Options"
          tabIndex={-1}
        >
          <div className="a11y-modal-header">
            <h4>Accessibility & Vision (§4.9)</h4>
            <button
              type="button"
              className="a11y-close-btn"
              onClick={() => setIsOpen(false)}
              aria-label="Close accessibility settings"
            >
              ×
            </button>
          </div>

          <div className="a11y-section">
            <label className="a11y-label" htmlFor="cb-select">
              <strong>Colour-Vision Deficiency Filter (§4.9b)</strong>
              <small className="muted block">
                Verify risk indicators survive without colour alone.
              </small>
            </label>
            <select
              id="cb-select"
              className="a11y-select"
              value={colorBlindMode}
              onChange={(e) => setColorBlindMode(e.target.value as ColorBlindMode)}
            >
              <option value="normal">Normal Vision (Default)</option>
              <option value="deuteranopia">Deuteranopia (Green-blind · ~6% of men)</option>
              <option value="protanopia">Protanopia (Red-blind · ~1% of men)</option>
              <option value="tritanopia">Tritanopia (Blue-blind · rare)</option>
              <option value="achromatopsia">Achromatopsia (Monochrome / Grayscale)</option>
            </select>
          </div>

          <div className="a11y-section">
            <label className="a11y-checkbox-row">
              <input
                type="checkbox"
                checked={reducedMotion}
                onChange={(e) => setReducedMotion(e.target.checked)}
              />
              <span>
                <strong>Reduced Motion (§4.9f)</strong>
                <small className="muted block">Disables all CSS animations and transitions.</small>
              </span>
            </label>
          </div>

          <div className="a11y-section">
            <label className="a11y-checkbox-row">
              <input
                type="checkbox"
                checked={highContrast}
                onChange={(e) => setHighContrast(e.target.checked)}
              />
              <span>
                <strong>High Contrast Mode (§4.9a)</strong>
                <small className="muted block">Enhances border definitions and focus indicators.</small>
              </span>
            </label>
          </div>

          <div className="a11y-modal-footer">
            <button
              type="button"
              className="button quiet small"
              onClick={() => {
                setColorBlindMode("normal");
                setReducedMotion(false);
                setHighContrast(false);
              }}
            >
              Reset to Defaults
            </button>
            <button
              type="button"
              className="button primary small"
              onClick={() => setIsOpen(false)}
            >
              Done
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
