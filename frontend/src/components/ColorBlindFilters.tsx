import React from "react";

/**
 * Standard Brettel / Viénot / Brettel-1997 color deficiency simulation matrices
 * for WCAG 2.1 AA & §4.9b verification.
 */
export function ColorBlindFilters() {
  return (
    <svg
      style={{ position: "absolute", width: 0, height: 0, overflow: "hidden" }}
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        {/* Protanopia (Red-blindness, ~1% of males) */}
        <filter id="protanopia-filter">
          <feColorMatrix
            type="matrix"
            values="0.567, 0.433, 0,     0, 0
                    0.558, 0.442, 0,     0, 0
                    0,     0.242, 0.758, 0, 0
                    0,     0,     0,     1, 0"
          />
        </filter>

        {/* Deuteranopia (Green-blindness, most common, ~6% of males) */}
        <filter id="deuteranopia-filter">
          <feColorMatrix
            type="matrix"
            values="0.625, 0.375, 0,   0, 0
                    0.7,   0.3,   0,   0, 0
                    0,     0.3,   0.7, 0, 0
                    0,     0,     0,   1, 0"
          />
        </filter>

        {/* Tritanopia (Blue-blindness, rare) */}
        <filter id="tritanopia-filter">
          <feColorMatrix
            type="matrix"
            values="0.95,  0.05,  0,     0, 0
                    0,     0.433, 0.567, 0, 0
                    0,     0.475, 0.525, 0, 0
                    0,     0,     0,     1, 0"
          />
        </filter>

        {/* Achromatopsia / Grayscale (Monochromacy / complete color blindness) */}
        <filter id="achromatopsia-filter">
          <feColorMatrix
            type="matrix"
            values="0.299, 0.587, 0.114, 0, 0
                    0.299, 0.587, 0.114, 0, 0
                    0.299, 0.587, 0.114, 0, 0
                    0,     0,     0,     1, 0"
          />
        </filter>
      </defs>
    </svg>
  );
}
