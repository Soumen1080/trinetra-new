import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";

export type PersonaType = "ciso" | "analyst" | "developer";

const PERSONAS = [
  {
    id: "ciso" as PersonaType,
    label: "Executive / CISO",
    targetPath: "/dashboard",
    description: "Readiness score, exposure & migration outlay in 0 clicks (§4.1)",
    icon: "👔",
  },
  {
    id: "analyst" as PersonaType,
    label: "Security Analyst",
    targetPath: "/explorer",
    description: "CBOM explorer, risk triage, and file:line evidence (§4.1)",
    icon: "🔍",
  },
  {
    id: "developer" as PersonaType,
    label: "Developer / Architect",
    targetPath: "/migration",
    description: "Wave sequencing, FIPS 203/204 radar, code remediation (§4.1)",
    icon: "🛠️",
  },
];

const STORAGE_KEY_PERSONA = "trinetra_active_persona";

export function PersonaSwitcher() {
  const navigate = useNavigate();
  const location = useLocation();

  const [activePersona, setActivePersona] = useState<PersonaType>(() => {
    return (localStorage.getItem(STORAGE_KEY_PERSONA) as PersonaType) || "analyst";
  });

  const handleSelectPersona = (id: PersonaType) => {
    setActivePersona(id);
    localStorage.setItem(STORAGE_KEY_PERSONA, id);
    const persona = PERSONAS.find((p) => p.id === id);
    if (persona && location.pathname === "/") {
      navigate(persona.targetPath);
    }
  };

  return (
    <div className="persona-switcher" aria-label="Role and persona view selector (§4.1b)">
      <span className="persona-label">Persona:</span>
      <select
        className="persona-select"
        value={activePersona}
        onChange={(e) => {
          const selected = e.target.value as PersonaType;
          handleSelectPersona(selected);
          const p = PERSONAS.find((item) => item.id === selected);
          if (p) navigate(p.targetPath);
        }}
        aria-label="Active role persona"
        title="Switch persona view to jump to your primary working surface (§4.1b)"
      >
        {PERSONAS.map((p) => (
          <option key={p.id} value={p.id}>
            {p.icon} {p.label}
          </option>
        ))}
      </select>
    </div>
  );
}
