import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Page } from "../components";

/**
 * Glossary page (§9.9 — §4.3c).
 * Defines every acronym in plain English. Every term is anchor-linked so
 * Tooltip's "Glossary ↗" links land on the correct definition.
 */
const TERMS: Array<{ term: string; definition: string; category: string }> = [
  {
    term: "CBOM",
    definition:
      "Cryptographic Bill of Materials — a machine-readable inventory of all cryptographic assets in a system. Analogous to a Software Bill of Materials (SBOM) but focused on crypto primitives, keys, certificates, and protocols.",
    category: "Standards",
  },
  {
    term: "CycloneDX",
    definition:
      "An open-source standard (OWASP) for documenting software supply-chain risk, extended to include cryptographic assets in version 1.6. Trinetra uses CycloneDX 1.6 CBOM as its canonical output format.",
    category: "Standards",
  },
  {
    term: "SPDX",
    definition:
      "Software Package Data Exchange — an ISO/IEC standard for communicating software component metadata, commonly used as an SBOM format.",
    category: "Standards",
  },
  {
    term: "CRQC",
    definition:
      "Cryptographically Relevant Quantum Computer — a quantum computer powerful enough to run Shor's algorithm at scale and break RSA, ECC, and DH. Does not exist yet, but is the threat model for post-quantum migration.",
    category: "Quantum",
  },
  {
    term: "Shor's algorithm",
    definition:
      "A quantum algorithm that factors large integers and solves discrete logarithms in polynomial time, breaking RSA, DSA, ECDSA, ECDH, and DH. A CRQC running Shor's would decrypt all historical traffic protected by these algorithms.",
    category: "Quantum",
  },
  {
    term: "Grover's algorithm",
    definition:
      "A quantum algorithm that provides a quadratic speedup over classical brute-force search, halving the effective security of symmetric algorithms. AES-128 becomes AES-64-equivalent under Grover — the standard response is to double key sizes (AES-256 remains safe).",
    category: "Quantum",
  },
  {
    term: "Mosca timing",
    definition:
      "A planning inequality: X + Z > Y means migrate now. X = years data must remain confidential, Y = estimated year a CRQC arrives, Z = years the migration will take. If X + Z exceeds Y, interception of current traffic creates future risk (HNDL).",
    category: "Risk",
  },
  {
    term: "HNDL",
    definition:
      "Harvest Now, Decrypt Later — an attack strategy where an adversary records encrypted traffic today and decrypts it when a CRQC becomes available. Long-lived sensitive data (medical records, state secrets, financial records) is the primary target.",
    category: "Risk",
  },
  {
    term: "PQC",
    definition:
      "Post-Quantum Cryptography — classical (software-only) algorithms designed to resist attacks from a CRQC. NIST standardised ML-KEM (Kyber), ML-DSA (Dilithium), and SLH-DSA (SPHINCS+) in FIPS 203/204/205.",
    category: "Cryptography",
  },
  {
    term: "ML-KEM",
    definition:
      "Module-Lattice Key Encapsulation Mechanism — NIST FIPS 203 (2024). The primary PQC key-establishment algorithm, replacing ECDH and RSA-KEM. Known as CRYSTALS-Kyber during standardisation.",
    category: "Cryptography",
  },
  {
    term: "ML-DSA",
    definition:
      "Module-Lattice Digital Signature Algorithm — NIST FIPS 204 (2024). The primary PQC signature scheme, replacing ECDSA and RSA-PSS. Known as CRYSTALS-Dilithium during standardisation.",
    category: "Cryptography",
  },
  {
    term: "CNSA 2.0",
    definition:
      "Commercial National Security Algorithm Suite 2.0 — NSA guidance requiring US national-security systems to adopt PQC by 2030 for new systems and 2033–2035 for legacy. Trinetra tracks compliance against these deadlines.",
    category: "Standards",
  },
  {
    term: "Quantum vulnerable",
    definition:
      "An artefact that uses an algorithm (RSA, ECC, DH, DSA) breakable by Shor's algorithm, or a symmetric algorithm with a key size that Grover's algorithm halves to below 128 bits. Needs a migration plan.",
    category: "Risk",
  },
  {
    term: "Priority",
    definition:
      "Trinetra's risk band — P0 (Critical: act now), P1 (High: plan next quarter), P2 (Moderate: track). Always paired with a text label and icon, never colour alone. Produced by the risk engine from Mosca, data classification, and exposure.",
    category: "Risk",
  },
  {
    term: "Needs context",
    definition:
      "Trinetra refuses to show a score when the required inputs are missing. 'Needs context' means: supply the asset's data classification, confidentiality life (X), or migration estimate (Z) to unlock a trustworthy assessment.",
    category: "Risk",
  },
  {
    term: "SARIF",
    definition:
      "Static Analysis Results Interchange Format — a JSON schema for communicating static analysis findings. Used by GitHub Code Scanning and Azure DevOps. Trinetra exports SARIF so findings can be raised as code-review annotations.",
    category: "Standards",
  },
  {
    term: "HSM",
    definition:
      "Hardware Security Module — a tamper-resistant device that generates, stores, and performs operations with cryptographic keys. Inventoried by Trinetra's PKCS#11 engine.",
    category: "Cryptography",
  },
  {
    term: "KMS",
    definition:
      "Key Management Service — a cloud-managed service for creating and controlling cryptographic keys (AWS KMS, Azure Key Vault, Google Cloud KMS). Trinetra's cloud scanner inventories keys and their algorithms.",
    category: "Cryptography",
  },
];

const CATEGORIES = [...new Set(TERMS.map((t) => t.category))];

export function GlossaryPage() {
  const [params] = useSearchParams();
  const [search, setSearch] = useState("");
  const [activeCategory, setActiveCategory] = useState<string>("");

  const filtered = TERMS.filter((term) => {
    const matchSearch =
      !search ||
      term.term.toLowerCase().includes(search.toLowerCase()) ||
      term.definition.toLowerCase().includes(search.toLowerCase());
    const matchCategory = !activeCategory || term.category === activeCategory;
    return matchSearch && matchCategory;
  });

  // Highlight the term linked from a Tooltip
  const highlightedTerm = params.get("highlight") ?? "";

  return (
    <Page
      title="Glossary"
      subtitle="Plain-language definitions for every term used in Trinetra. Hover over ⓘ on any screen to link here."
    >
      <div className="glossary-controls">
        <input
          className="glossary-search"
          placeholder="Search terms and definitions…"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          aria-label="Filter glossary terms"
        />
        <div className="glossary-categories" role="group" aria-label="Filter by category">
          <button
            className={!activeCategory ? "category-chip active" : "category-chip"}
            onClick={() => setActiveCategory("")}
          >
            All
          </button>
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              className={activeCategory === cat ? "category-chip active" : "category-chip"}
              onClick={() => setActiveCategory(activeCategory === cat ? "" : cat)}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      <section className="glossary">
        {filtered.length ? (
          filtered.map(({ term, definition, category }) => (
            <article
              key={term}
              id={term.toLowerCase()}
              className={`glossary-article${highlightedTerm.toLowerCase() === term.toLowerCase() ? " highlighted" : ""}`}
            >
              <div className="glossary-term-header">
                <h2>{term}</h2>
                <span className="glossary-category">{category}</span>
              </div>
              <p>{definition}</p>
            </article>
          ))
        ) : (
          <p className="muted">No terms match that search.</p>
        )}
      </section>
    </Page>
  );
}
