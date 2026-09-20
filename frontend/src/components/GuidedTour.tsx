import { useState, useEffect, useCallback } from "react";
import { useNavigate, useLocation } from "react-router-dom";

export interface TourStep {
  id: string;
  title: string;
  targetPath: string;
  targetPersona: "Executive / CISO" | "Security Analyst" | "Developer & Architect";
  headline: string;
  description: string;
  keyCallout: string;
}

const TOUR_STEPS: TourStep[] = [
  {
    id: "step-dashboard",
    title: "Executive Readiness Overview",
    targetPath: "/dashboard",
    targetPersona: "Executive / CISO",
    headline: "Answers in 10 seconds: 'How exposed are we, and what will it cost?'",
    description:
      "The Dashboard delivers high-level posture metrics with zero jargon. You see the overall Posture Score, total vulnerable assets, and estimated capital outlay.",
    keyCallout:
      "Look for the 'Top 5 Things to Fix This Quarter' panel — the single most useful element for non-cryptographer leadership.",
  },
  {
    id: "step-explorer",
    title: "CBOM Explorer & Evidence Drawer",
    targetPath: "/explorer",
    targetPersona: "Security Analyst",
    headline: "Answers: 'Which findings are real, and which do I fix first?'",
    description:
      "The analyst's primary working surface. Virtualised to smoothly scroll 100,000 findings, pre-sorted by risk descending with faceted filters.",
    keyCallout:
      "Click any finding row to open the Artefact Drawer — inspect syntax-highlighted code at exact file:line coordinates and Mosca arithmetic.",
  },
  {
    id: "step-risk",
    title: "Risk Visualisations & Mosca Timeline",
    targetPath: "/risk",
    targetPersona: "Security Analyst",
    headline: "Answers: 'When will quantum computers break our data secrecy?'",
    description:
      "Interactive threat modeling. Features the Mosca Timeline Visualiser ($X+Z > Y$) with live scenario slider, the 5×5 Risk Heatmap, and the Blast Radius Dependency Graph.",
    keyCallout:
      "Every chart includes a '?' button explaining how to read it, plus an accessible 'Show table ♿' toggle.",
  },
  {
    id: "step-migration",
    title: "Migration Roadmap & Remediation",
    targetPath: "/migration",
    targetPersona: "Developer & Architect",
    headline: "Answers: 'What do I change in my code, and by when?'",
    description:
      "Turn analysis into execution. The Roadmap Gantt organizes transitions into Waves with HTML5 drag-and-drop reprioritisation and Mosca breach alerts.",
    keyCallout:
      "Use the Recommendation Workspace to compare current classical crypto against NIST FIPS 203/204 standards on a 5-axis trade-off radar.",
  },
];

const STORAGE_KEY = "trinetra_tour_completed";

interface GuidedTourProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export function GuidedTour({ isOpen, onClose }: GuidedTourProps) {
  const navigate = useNavigate();
  const location = useLocation();

  const [active, setActive] = useState<boolean>(() => {
    if (isOpen !== undefined) return isOpen;
    return localStorage.getItem(STORAGE_KEY) !== "true";
  });
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(0);

  const step = TOUR_STEPS[currentStepIndex];

  const handleClose = useCallback(() => {
    localStorage.setItem(STORAGE_KEY, "true");
    setActive(false);
    if (onClose) onClose();
  }, [onClose]);

  // Synchronize when parent controls isOpen
  useEffect(() => {
    if (isOpen !== undefined) {
      setActive(isOpen);
      if (isOpen) setCurrentStepIndex(0);
    }
  }, [isOpen]);

  // Navigate to step target route if not already there
  useEffect(() => {
    if (active && step && location.pathname !== step.targetPath) {
      navigate(step.targetPath);
    }
  }, [active, step, location.pathname, navigate]);

  // Keyboard navigation: Escape to dismiss, Arrow keys to navigate
  useEffect(() => {
    if (!active) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        handleClose();
      } else if (e.key === "ArrowRight") {
        if (currentStepIndex < TOUR_STEPS.length - 1) {
          setCurrentStepIndex((prev) => prev + 1);
        }
      } else if (e.key === "ArrowLeft") {
        if (currentStepIndex > 0) {
          setCurrentStepIndex((prev) => prev - 1);
        }
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [active, currentStepIndex, handleClose]);

  if (!active || !step) return null;

  const isLast = currentStepIndex === TOUR_STEPS.length - 1;

  return (
    <div className="tour-backdrop" role="dialog" aria-modal="true" aria-label="Guided Product Tour">
      <div className="tour-card">
        {/* Header bar */}
        <div className="tour-header">
          <div className="tour-step-badge">
            Step {currentStepIndex + 1} of {TOUR_STEPS.length}
          </div>
          <span className="tour-persona-tag">Primary: {step.targetPersona}</span>
          <button
            className="tour-close-btn"
            onClick={handleClose}
            aria-label="Close guided tour"
            title="Close tour (Esc)"
          >
            ×
          </button>
        </div>

        {/* Content */}
        <div className="tour-body">
          <h2 className="tour-title">{step.title}</h2>
          <p className="tour-headline">{step.headline}</p>
          <p className="tour-desc">{step.description}</p>
          <div className="tour-callout">
            <span className="callout-bulb">💡</span>
            <p>{step.keyCallout}</p>
          </div>
        </div>

        {/* Footer actions & indicators */}
        <div className="tour-footer">
          <div className="tour-dots">
            {TOUR_STEPS.map((s, idx) => (
              <button
                key={s.id}
                className={`tour-dot ${idx === currentStepIndex ? "active" : ""}`}
                onClick={() => setCurrentStepIndex(idx)}
                aria-label={`Jump to step ${idx + 1}: ${s.title}`}
              />
            ))}
          </div>

          <div className="tour-action-group">
            <button
              className="button quiet tour-skip-btn"
              onClick={handleClose}
            >
              Skip tour
            </button>
            {currentStepIndex > 0 && (
              <button
                className="button secondary"
                onClick={() => setCurrentStepIndex((prev) => prev - 1)}
              >
                ← Back
              </button>
            )}
            <button
              className="button primary"
              onClick={() => {
                if (isLast) {
                  handleClose();
                } else {
                  setCurrentStepIndex((prev) => prev + 1);
                }
              }}
            >
              {isLast ? "Finish Tour ✓" : "Next Screen →"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
