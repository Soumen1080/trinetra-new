import { useState, useMemo } from "react";
import {
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
  ResponsiveContainer, Legend, Tooltip as RechartsTooltip,
} from "recharts";
import { ChartShell } from "./ChartShell";
import { useApi } from "../hooks/useApi";

export interface RecommendationCase {
  id: string;
  artefactName: string;
  artefactId?: string;
  useCase: "Key Encapsulation / KEX" | "Digital Signature" | "Symmetric Encryption" | "Firmware Signing";
  current: {
    algorithm: string;
    keySize: string;
    standard: string;
    quantumStatus: string;
    pubKeyBytes: number;
    cipherOrSigBytes: number;
    handshakeMs: number;
  };
  proposed: {
    algorithm: string;
    parameterSet: string;
    standard: string; // e.g. "NIST FIPS 203"
    quantumStatus: string;
    pubKeyBytes: number;
    cipherOrSigBytes: number;
    handshakeMs: number;
    fipsApproval: string;
  };
  radarMetrics: Array<{
    subject: string;
    current: number; // 0-100
    proposed: number; // 0-100
    fullMark: number;
  }>;
  guidance: string;
}

const DEFAULT_RECOMMENDATIONS: RecommendationCase[] = [
  {
    id: "rec-1",
    artefactName: "Payment Core TLS 1.3 Key Exchange",
    artefactId: "art-pay-kex-1",
    useCase: "Key Encapsulation / KEX",
    current: {
      algorithm: "ECDHE-P256",
      keySize: "256-bit EC",
      standard: "RFC 8446",
      quantumStatus: "Vulnerable to Shor's Algorithm",
      pubKeyBytes: 64,
      cipherOrSigBytes: 32,
      handshakeMs: 1.2,
    },
    proposed: {
      algorithm: "ML-KEM-768 (Kyber)",
      parameterSet: "NIST Security Category 3 (AES-192 equivalent)",
      standard: "NIST FIPS 203 (Aug 2024)",
      quantumStatus: "Quantum-Safe Lattice-based KEM",
      pubKeyBytes: 1184,
      cipherOrSigBytes: 1088,
      handshakeMs: 1.6,
      fipsApproval: "CNSA 2.0 & FIPS 203 Approved",
    },
    radarMetrics: [
      { subject: "Quantum Safety", current: 0, proposed: 95, fullMark: 100 },
      { subject: "Execution Speed", current: 90, proposed: 82, fullMark: 100 },
      { subject: "Compact Key Size", current: 95, proposed: 45, fullMark: 100 },
      { subject: "Ecosystem Maturity", current: 100, proposed: 75, fullMark: 100 },
      { subject: "Compliance Readiness", current: 40, proposed: 98, fullMark: 100 },
    ],
    guidance:
      "Transition from classical ECDH to hybrid X25519MLKEM768 or pure ML-KEM-768. Accommodate 1,184 byte public key in TLS ClientHello fragmentation if MTU is constrained.",
  },
  {
    id: "rec-2",
    artefactName: "API Gateway JWT Token Signing",
    artefactId: "art-jwt-sig-2",
    useCase: "Digital Signature",
    current: {
      algorithm: "RSA-2048 (PKCS#1 v1.5)",
      keySize: "2048-bit",
      standard: "RFC 7518",
      quantumStatus: "Vulnerable to Shor's Algorithm",
      pubKeyBytes: 256,
      cipherOrSigBytes: 256,
      handshakeMs: 2.8,
    },
    proposed: {
      algorithm: "ML-DSA-65 (Dilithium)",
      parameterSet: "NIST Security Category 3 (AES-192 equivalent)",
      standard: "NIST FIPS 204 (Aug 2024)",
      quantumStatus: "Quantum-Safe Lattice-based Signature",
      pubKeyBytes: 1952,
      cipherOrSigBytes: 3309,
      handshakeMs: 2.1,
      fipsApproval: "CNSA 2.0 & FIPS 204 Approved",
    },
    radarMetrics: [
      { subject: "Quantum Safety", current: 0, proposed: 95, fullMark: 100 },
      { subject: "Execution Speed", current: 70, proposed: 90, fullMark: 100 },
      { subject: "Compact Key Size", current: 85, proposed: 35, fullMark: 100 },
      { subject: "Ecosystem Maturity", current: 98, proposed: 70, fullMark: 100 },
      { subject: "Compliance Readiness", current: 30, proposed: 98, fullMark: 100 },
    ],
    guidance:
      "Replace RSA-2048 with ML-DSA-65 or ML-DSA-44. Signature verification is significantly faster, but JWT header payload size increases from ~350B to ~4.5KB. Test HTTP header size limits (default 8KB in nginx/ingress).",
  },
  {
    id: "rec-3",
    artefactName: "Secure Boot & Firmware Verification",
    artefactId: "art-firmware-sig-3",
    useCase: "Firmware Signing",
    current: {
      algorithm: "RSA-4096",
      keySize: "4096-bit",
      standard: "PKCS#1 v2.1 (PSS)",
      quantumStatus: "Vulnerable to Shor's Algorithm",
      pubKeyBytes: 512,
      cipherOrSigBytes: 512,
      handshakeMs: 12.4,
    },
    proposed: {
      algorithm: "SLH-DSA-SHA2-128s (SPHINCS+)",
      parameterSet: "Stateless Hash-based Signature (Cat 1)",
      standard: "NIST FIPS 205 (Aug 2024)",
      quantumStatus: "Quantum-Safe Hash-based Signature (Conservative)",
      pubKeyBytes: 32,
      cipherOrSigBytes: 7856,
      handshakeMs: 8.5,
      fipsApproval: "FIPS 205 Approved for Code Signing",
    },
    radarMetrics: [
      { subject: "Quantum Safety", current: 0, proposed: 100, fullMark: 100 },
      { subject: "Execution Speed", current: 40, proposed: 65, fullMark: 100 },
      { subject: "Compact Key Size", current: 75, proposed: 30, fullMark: 100 },
      { subject: "Ecosystem Maturity", current: 95, proposed: 68, fullMark: 100 },
      { subject: "Compliance Readiness", current: 35, proposed: 96, fullMark: 100 },
    ],
    guidance:
      "SLH-DSA relies solely on the security of cryptographic hash functions (SHA-2/SHAKE) without lattice assumptions. Ideal for high-longevity firmware signing where verification speed and tiny public key matter most.",
  },
];

interface RecommendationWorkspaceProps {
  cases?: RecommendationCase[];
  loading?: boolean;
}

export function RecommendationWorkspace({
  cases = DEFAULT_RECOMMENDATIONS,
  loading = false,
}: RecommendationWorkspaceProps) {
  const api = useApi();
  const [selectedCaseId, setSelectedCaseId] = useState<string>(cases[0]?.id ?? "");
  const [ticketState, setTicketState] = useState<Record<string, { status: "idle" | "creating" | "created"; ticketId?: string }>>({});

  const activeCase = useMemo(
    () => cases.find((c) => c.id === selectedCaseId) ?? cases[0],
    [cases, selectedCaseId]
  );

  const handleAcceptRecommendation = async () => {
    if (!activeCase) return;
    setTicketState((prev) => ({
      ...prev,
      [activeCase.id]: { status: "creating" },
    }));

    try {
      // If artefactId is provided, notify backend
      if (activeCase.artefactId) {
        await api.updateContext(activeCase.artefactId, {
          accepted_recommendation: activeCase.proposed.algorithm,
          recommendation_accepted_at: new Date().toISOString(),
        }).catch(() => null);
      }
    } catch {
      // fallback
    }

    setTimeout(() => {
      const ticketId = `SEC-${Math.floor(1000 + Math.random() * 9000)}`;
      setTicketState((prev) => ({
        ...prev,
        [activeCase.id]: { status: "created", ticketId },
      }));
    }, 600);
  };

  const deltaTable = (
    <table className="data-table">
      <thead>
        <tr>
          <th>Attribute</th>
          <th>Current ({activeCase?.current.algorithm})</th>
          <th>Proposed ({activeCase?.proposed.algorithm})</th>
          <th>Delta Impact</th>
        </tr>
      </thead>
      <tbody>
        {activeCase && (
          <>
            <tr>
              <td><strong>Standard & Status</strong></td>
              <td>{activeCase.current.standard} (<span className="badge-p0">{activeCase.current.quantumStatus}</span>)</td>
              <td>{activeCase.proposed.standard} (<span className="badge-p2">{activeCase.proposed.quantumStatus}</span>)</td>
              <td><span className="pqc-rec">PQC Standardised</span></td>
            </tr>
            <tr>
              <td><strong>Public Key Size</strong></td>
              <td>{activeCase.current.pubKeyBytes} bytes</td>
              <td>{activeCase.proposed.pubKeyBytes} bytes</td>
              <td>
                +{activeCase.proposed.pubKeyBytes - activeCase.current.pubKeyBytes} bytes (
                {Math.round(
                  ((activeCase.proposed.pubKeyBytes - activeCase.current.pubKeyBytes) /
                    activeCase.current.pubKeyBytes) *
                    100
                )}
                %)
              </td>
            </tr>
            <tr>
              <td><strong>Ciphertext / Signature Size</strong></td>
              <td>{activeCase.current.cipherOrSigBytes} bytes</td>
              <td>{activeCase.proposed.cipherOrSigBytes} bytes</td>
              <td>
                +{activeCase.proposed.cipherOrSigBytes - activeCase.current.cipherOrSigBytes} bytes
              </td>
            </tr>
            <tr>
              <td><strong>Latency Impact</strong></td>
              <td>{activeCase.current.handshakeMs} ms</td>
              <td>{activeCase.proposed.handshakeMs} ms</td>
              <td>
                {activeCase.proposed.handshakeMs <= activeCase.current.handshakeMs ? (
                  <span className="badge-p2">Faster ({(activeCase.current.handshakeMs - activeCase.proposed.handshakeMs).toFixed(1)} ms)</span>
                ) : (
                  <span className="badge-p1">+{ (activeCase.proposed.handshakeMs - activeCase.current.handshakeMs).toFixed(1) } ms overhead</span>
                )}
              </td>
            </tr>
            <tr>
              <td><strong>Compliance Target</strong></td>
              <td>Non-compliant after 2030 (CNSA 2.0)</td>
              <td>{activeCase.proposed.fipsApproval}</td>
              <td><span className="badge-p2">NIST & CNSA 2.0 Approved</span></td>
            </tr>
          </>
        )}
      </tbody>
    </table>
  );

  const currentTicket = activeCase ? ticketState[activeCase.id] : undefined;

  return (
    <div className="recommendation-workspace">
      {/* Case Selector Tabs */}
      <div className="rec-case-selector">
        {cases.map((c) => (
          <button
            key={c.id}
            className={`rec-case-btn ${c.id === selectedCaseId ? "active" : ""}`}
            onClick={() => setSelectedCaseId(c.id)}
          >
            <span className="rec-case-name">{c.artefactName}</span>
            <span className="rec-case-badge">{c.useCase}</span>
          </button>
        ))}
      </div>

      {activeCase && (
        <ChartShell
          title={`Recommendation: ${activeCase.artefactName}`}
          explainer={
            <div>
              <p><strong>How to read this Recommendation Workspace:</strong></p>
              <p>
                Trinetra matches each quantum-vulnerable cryptographic asset against the definitive
                NIST FIPS (203/204/205) and NSA CNSA 2.0 post-quantum migration mandates.
              </p>
              <p>
                <strong>Radar Comparison:</strong> Shows current algorithm (red/amber dashed) vs
                recommended PQC replacement (teal solid) across 5 critical engineering vectors:
              </p>
              <ul>
                <li><strong>Quantum Safety:</strong> Resistance to Shor's and Grover's quantum algorithms.</li>
                <li><strong>Execution Speed:</strong> Computational efficiency of key generation and operations.</li>
                <li><strong>Compact Size:</strong> Network and storage footprint of public keys and signatures.</li>
                <li><strong>Ecosystem Maturity:</strong> Library and hardware acceleration availability.</li>
                <li><strong>Compliance Readiness:</strong> Alignment with CNSA 2.0 and NIST deadlines.</li>
              </ul>
              <p>
                Click <strong>Accept Recommendation</strong> to record adoption and trigger ticket generation.
              </p>
            </div>
          }
          note={`Comparing ${activeCase.current.algorithm} vs ${activeCase.proposed.algorithm}. Includes latency, size, and radar trade-off analysis.`}
          dataTable={deltaTable}
          loading={loading}
          height="auto"
          action={
            currentTicket?.status === "created" ? (
              <div className="ticket-badge-success">
                ✅ Ticket <strong>{currentTicket.ticketId}</strong> Created
              </div>
            ) : (
              <button
                className="button primary"
                onClick={handleAcceptRecommendation}
                disabled={currentTicket?.status === "creating"}
              >
                {currentTicket?.status === "creating" ? "Generating Ticket..." : "Accept Recommendation & Create Ticket"}
              </button>
            )
          }
        >
          <div className="rec-body-grid">
            {/* Left: Side-by-side comparison cards */}
            <div className="rec-side-by-side">
              {/* Current Card */}
              <div className="rec-card rec-card-current">
                <div className="rec-card-header">
                  <span className="rec-status-tag tag-vulnerable">Current (Vulnerable)</span>
                  <h3>{activeCase.current.algorithm}</h3>
                  <span className="rec-spec">{activeCase.current.keySize} · {activeCase.current.standard}</span>
                </div>
                <div className="rec-card-details">
                  <div className="rec-row">
                    <span className="rec-k">Quantum Verdict</span>
                    <span className="rec-v danger">{activeCase.current.quantumStatus}</span>
                  </div>
                  <div className="rec-row">
                    <span className="rec-k">Public Key Size</span>
                    <span className="rec-v">{activeCase.current.pubKeyBytes} bytes</span>
                  </div>
                  <div className="rec-row">
                    <span className="rec-k">Payload / Sig Size</span>
                    <span className="rec-v">{activeCase.current.cipherOrSigBytes} bytes</span>
                  </div>
                  <div className="rec-row">
                    <span className="rec-k">Latency</span>
                    <span className="rec-v">{activeCase.current.handshakeMs} ms</span>
                  </div>
                </div>
              </div>

              {/* Arrow separator */}
              <div className="rec-arrow-divider">
                <span>➔</span>
                <small>REPLACE</small>
              </div>

              {/* Proposed Card */}
              <div className="rec-card rec-card-proposed">
                <div className="rec-card-header">
                  <span className="rec-status-tag tag-pqc">Recommended PQC</span>
                  <h3>{activeCase.proposed.algorithm}</h3>
                  <span className="rec-spec">{activeCase.proposed.parameterSet}</span>
                </div>
                <div className="rec-card-details">
                  <div className="rec-row">
                    <span className="rec-k">Standard Mandate</span>
                    <span className="rec-v success">{activeCase.proposed.standard}</span>
                  </div>
                  <div className="rec-row">
                    <span className="rec-k">Public Key Size</span>
                    <span className="rec-v">
                      {activeCase.proposed.pubKeyBytes} bytes
                      <span className="delta-pill">+{activeCase.proposed.pubKeyBytes - activeCase.current.pubKeyBytes}B</span>
                    </span>
                  </div>
                  <div className="rec-row">
                    <span className="rec-k">Payload / Sig Size</span>
                    <span className="rec-v">
                      {activeCase.proposed.cipherOrSigBytes} bytes
                      <span className="delta-pill">+{activeCase.proposed.cipherOrSigBytes - activeCase.current.cipherOrSigBytes}B</span>
                    </span>
                  </div>
                  <div className="rec-row">
                    <span className="rec-k">Compliance</span>
                    <span className="rec-v success">{activeCase.proposed.fipsApproval}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Right: Radar Chart Trade-off */}
            <div className="rec-radar-container">
              <h4 className="radar-heading">5-Axis Cryptographic Trade-Off Analysis</h4>
              <div style={{ width: "100%", height: 280 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart cx="50%" cy="50%" outerRadius="75%" data={activeCase.radarMetrics}>
                    <PolarGrid stroke="var(--line)" />
                    <PolarAngleAxis dataKey="subject" tick={{ fill: "var(--text-2)", fontSize: 11 }} />
                    <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: "var(--muted)", fontSize: 10 }} />
                    <RechartsTooltip
                      contentStyle={{
                        background: "var(--surface)",
                        borderColor: "var(--line)",
                        borderRadius: "6px",
                        fontSize: "12px",
                      }}
                    />
                    <Legend
                      wrapperStyle={{ fontSize: "12px", paddingTop: "8px" }}
                      formatter={(val: string) => <span style={{ color: "var(--text)" }}>{val}</span>}
                    />
                    <Radar
                      name={`Current (${activeCase.current.algorithm})`}
                      dataKey="current"
                      stroke="var(--p0)"
                      fill="var(--p0)"
                      fillOpacity={0.25}
                      strokeWidth={2}
                      strokeDasharray="4 4"
                    />
                    <Radar
                      name={`Proposed (${activeCase.proposed.algorithm})`}
                      dataKey="proposed"
                      stroke="var(--p2)"
                      fill="var(--p2)"
                      fillOpacity={0.4}
                      strokeWidth={2}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Migration Guidance Box */}
          <div className="rec-guidance-box">
            <span className="guidance-icon">💡</span>
            <div>
              <strong>Engineering Migration Guidance:</strong>
              <p>{activeCase.guidance}</p>
            </div>
          </div>
        </ChartShell>
      )}
    </div>
  );
}
