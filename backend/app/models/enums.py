"""Canonical vocabulary for the Trinetra platform.

P6 — one canonical vocabulary, translated at the boundaries. **snake_case is
canonical.** Every value in this module is the internal spelling; translation to
and from the CycloneDX wire format happens in ``app.schemas.vocab`` and nowhere
else.

Nothing in this module may import from elsewhere in the application. It is the
root of the dependency graph: engines, models and schemas all read from here.
"""

from __future__ import annotations

from enum import Enum


class _CanonicalEnum(str, Enum):  # noqa: UP042
    """Base for canonical vocabularies.

    Inherits from ``str`` so values serialise transparently to JSON and compare
    equal to their wire spelling without explicit conversion. ``StrEnum`` would
    be the modern spelling, but it lowercases member lookup differently and the
    canonical values here are the contract -- so the explicit base is kept.
    """

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)

    @classmethod
    def values(cls) -> tuple[str, ...]:
        return tuple(member.value for member in cls)

    @classmethod
    def has_value(cls, value: str) -> bool:
        return value in cls._value2member_map_


# ---------------------------------------------------------------------------
# 1.1 Asset taxonomy  (covers R1-R7)
# ---------------------------------------------------------------------------


class AssetType(_CanonicalEnum):
    """What kind of cryptographic asset a finding describes.

    Mirrors the CycloneDX 1.6 ``cryptoProperties.assetType`` value set, extended
    with the two infrastructure types Trinetra discovers that CycloneDX models as
    ``related-crypto-material``.
    """

    ALGORITHM = "algorithm"
    KEY = "key"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    LIBRARY = "library"
    HARDWARE_MODULE = "hardware_module"
    CLOUD_SERVICE = "cloud_service"
    RELATED_MATERIAL = "related_material"


class Primitive(_CanonicalEnum):
    """The cryptographic primitive an algorithm implements.

    Drives the attack model: only ``pke``, ``signature``, ``key_agreement`` and
    ``kem`` are Shor-breakable, while ``block_cipher`` and ``hash`` are merely
    Grover-weakened. The risk engine reads this field, never the algorithm name.
    """

    BLOCK_CIPHER = "block_cipher"
    STREAM_CIPHER = "stream_cipher"
    HASH = "hash"
    MAC = "mac"
    AEAD = "aead"
    SIGNATURE = "signature"
    PKE = "pke"
    KEM = "kem"
    KEY_AGREEMENT = "key_agreement"
    KDF = "kdf"
    DRBG = "drbg"
    OTHER = "other"


class Purpose(_CanonicalEnum):
    """What the artefact is used *for* at the point of detection.

    Distinct from :class:`Primitive`: RSA is a ``pke`` primitive that may be used
    for ``key_encapsulation`` in one call site and ``digital_signature`` in
    another, and the two carry different urgency (confidentiality risk is
    retroactive, authenticity risk is not).
    """

    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    DIGITAL_SIGNATURE = "digital_signature"
    VERIFY = "verify"
    KEY_ENCAPSULATION = "key_encapsulation"
    KEY_AGREEMENT = "key_agreement"
    KEY_DERIVATION = "key_derivation"
    HASHING = "hashing"
    AUTHENTICATION = "authentication"
    INTEGRITY = "integrity"
    RANDOM_GENERATION = "random_generation"
    OTHER = "other"


class CipherMode(_CanonicalEnum):
    """Block cipher mode of operation.

    Load-bearing for R19: ``AES-128`` alone is not an answer. ECB is a finding in
    its own right regardless of key size.
    """

    ECB = "ecb"
    CBC = "cbc"
    CTR = "ctr"
    GCM = "gcm"
    CCM = "ccm"
    OFB = "ofb"
    CFB = "cfb"
    XTS = "xts"
    SIV = "siv"
    POLY1305 = "poly1305"
    OTHER = "other"


class Padding(_CanonicalEnum):
    """Padding scheme. ``pkcs1_v15`` and ``raw`` are findings in themselves."""

    PKCS1_V15 = "pkcs1_v15"
    OAEP = "oaep"
    PSS = "pss"
    PKCS7 = "pkcs7"
    ANSI_X923 = "ansi_x923"
    ISO10126 = "iso10126"
    ZERO = "zero"
    RAW = "raw"
    NONE = "none"
    OTHER = "other"


# ---------------------------------------------------------------------------
# 1.3 Key material
# ---------------------------------------------------------------------------


class KeyState(_CanonicalEnum):
    """Lifecycle state of a key, per NIST SP 800-57."""

    PRE_ACTIVATION = "pre_activation"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"
    COMPROMISED = "compromised"
    DESTROYED = "destroyed"
    UNKNOWN = "unknown"


class KeyStorageLocation(_CanonicalEnum):
    """Where the key material actually lives.

    Ordered loosely from worst to best. ``source_code`` is always a finding: a
    key in a repository is disclosed to everyone with read access and to every
    system that has ever mirrored it.
    """

    SOURCE_CODE = "source_code"
    CONFIG_FILE = "config_file"
    ENVIRONMENT_VARIABLE = "environment_variable"
    KEYSTORE_FILE = "keystore_file"
    CONTAINER_IMAGE = "container_image"
    SECRETS_MANAGER = "secrets_manager"
    CLOUD_KMS = "cloud_kms"
    HSM = "hsm"
    TPM = "tpm"
    SMARTCARD = "smartcard"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# 1.5 Protocols
# ---------------------------------------------------------------------------


class ProtocolName(_CanonicalEnum):
    TLS = "tls"
    DTLS = "dtls"
    SSH = "ssh"
    IPSEC = "ipsec"
    IKE = "ike"
    WIREGUARD = "wireguard"
    SMIME = "smime"
    OPENPGP = "openpgp"
    KERBEROS = "kerberos"
    SAML = "saml"
    OIDC = "oidc"
    OTHER = "other"


# ---------------------------------------------------------------------------
# 1.7 / 1.8 Infrastructure
# ---------------------------------------------------------------------------


class CloudProvider(_CanonicalEnum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    IBM = "ibm"
    ORACLE = "oracle"
    ON_PREMISE = "on_premise"
    OTHER = "other"


class CloudServiceKind(_CanonicalEnum):
    KMS = "kms"
    CLOUD_HSM = "cloud_hsm"
    CERTIFICATE_MANAGER = "certificate_manager"
    SECRETS_MANAGER = "secrets_manager"
    VAULT = "vault"
    OTHER = "other"


class KeyManagementKind(_CanonicalEnum):
    """Who controls the key.

    ``provider_managed`` keys cannot be migrated by the customer on their own
    schedule, which is a migration-complexity input, not merely a label.
    """

    PROVIDER_MANAGED = "provider_managed"
    CUSTOMER_MANAGED = "customer_managed"
    CUSTOMER_SUPPLIED = "customer_supplied"
    UNKNOWN = "unknown"


class FipsStatus(_CanonicalEnum):
    FIPS_140_2 = "fips_140_2"
    FIPS_140_3 = "fips_140_3"
    NON_FIPS = "non_fips"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# 1.9 Business context
# ---------------------------------------------------------------------------


class BusinessCriticality(_CanonicalEnum):
    """Business criticality of the owning system.

    A string enum rather than a bare 1-5 integer so that an unset value is
    ``unknown`` and visibly so, rather than silently becoming 3 (P3).
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class DataClassification(_CanonicalEnum):
    RESTRICTED = "restricted"
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"
    UNKNOWN = "unknown"


class ExposureLevel(_CanonicalEnum):
    """Network reachability of the system holding the artefact.

    Drives HNDL urgency: internet-exposed traffic can be recorded today by an
    adversary with no access to the network, which is what makes it the
    highest-priority confidentiality risk.
    """

    INTERNET = "internet"
    PARTNER = "partner"
    INTERNAL = "internal"
    ISOLATED = "isolated"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Provenance and evidence  (P4)
# ---------------------------------------------------------------------------


class ProvenanceTier(_CanonicalEnum):
    """Which tier supplied a context field.

    Strict precedence, strongest first. Every resolved context field records its
    tier so that no number can be presented without its origin (P4).
    """

    USER = "user"
    SCANNER_EVIDENCE = "scanner_evidence"
    ORG_PRESET = "org_preset"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        """Lower rank wins. Used by the context resolver's precedence chain."""
        return _PROVENANCE_RANK[self]


_PROVENANCE_RANK: dict[ProvenanceTier, int] = {
    ProvenanceTier.USER: 0,
    ProvenanceTier.SCANNER_EVIDENCE: 1,
    ProvenanceTier.ORG_PRESET: 2,
    ProvenanceTier.UNKNOWN: 3,
}


class DetectionMethod(_CanonicalEnum):
    """How a finding was detected. Feeds the confidence shown in the UI."""

    SEMGREP_PATTERN = "semgrep_pattern"
    SEMGREP_TAINT = "semgrep_taint"
    TREE_SITTER_AST = "tree_sitter_ast"
    DEPENDENCY_MANIFEST = "dependency_manifest"
    SBOM_INGEST = "sbom_ingest"
    BINARY_SYMBOL = "binary_symbol"
    BINARY_CONSTANT = "binary_constant"
    CERTIFICATE_PARSE = "certificate_parse"
    TLS_HANDSHAKE = "tls_handshake"
    PKCS11_ENUMERATION = "pkcs11_enumeration"
    CLOUD_API = "cloud_api"
    CONFIG_PARSE = "config_parse"
    ENTROPY_HEURISTIC = "entropy_heuristic"
    OTHER = "other"


class Confidence(_CanonicalEnum):
    """Three levels only.

    A numeric confidence invites false precision and arithmetic that the
    underlying evidence does not support. :meth:`downgrade` implements the
    one-level drop the risk engine applies when any factor lacked evidence.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]

    def downgrade(self, steps: int = 1) -> Confidence:
        """Return this confidence lowered by ``steps``, floored at ``LOW``."""
        if steps < 0:
            raise ValueError("steps must be non-negative")
        order = [Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW]
        index = min(order.index(self) + steps, len(order) - 1)
        return order[index]

    @classmethod
    def weaker(cls, *values: Confidence) -> Confidence:
        """Return the weakest of ``values``.

        The combined confidence of two tracks is the weaker of the two, never an
        average -- averaging would let a high-confidence track mask a
        low-confidence one.
        """
        if not values:
            raise ValueError("weaker() requires at least one confidence value")
        return max(values, key=lambda c: c.rank)


_CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.HIGH: 0,
    Confidence.MEDIUM: 1,
    Confidence.LOW: 2,
}


# ---------------------------------------------------------------------------
# Quantum risk vocabulary
# ---------------------------------------------------------------------------


class QuantumVulnerability(_CanonicalEnum):
    """How an algorithm fares against a cryptographically relevant quantum
    computer.

    ``classically_broken`` is deliberately separate from the quantum categories:
    MD5 and SHA-1 are today's problem, not 2035's, and conflating the two
    misrepresents urgency in both directions.
    """

    SHOR_BROKEN = "shor_broken"
    GROVER_WEAKENED = "grover_weakened"
    QUANTUM_SAFE = "quantum_safe"
    CLASSICALLY_BROKEN = "classically_broken"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class NistSecurityLevel(_CanonicalEnum):
    """NIST PQC security category.

    ``LEVEL_0`` is Trinetra's own extension meaning "no security remains against
    a CRQC" -- the honest description of RSA and ECC in a post-quantum world.
    """

    LEVEL_0 = "0"
    LEVEL_1 = "1"
    LEVEL_2 = "2"
    LEVEL_3 = "3"
    LEVEL_4 = "4"
    LEVEL_5 = "5"
    UNKNOWN = "unknown"


class AssessmentStatus(_CanonicalEnum):
    """Why an artefact does or does not carry a score.

    ``NEEDS_CONTEXT`` is load-bearing and must never be folded into a low-risk
    band: those artefacts are *unassessed*, not safe. P3 requires that the
    distinction survive all the way to the UI.
    """

    SCORED = "scored"
    NEEDS_CONTEXT = "needs_context"
    POLICY_DECIDED = "policy_decided"
    DEPENDENCY_ONLY = "dependency_only"
    NOT_APPLICABLE = "not_applicable"


class Priority(_CanonicalEnum):
    P0 = "p0"
    P1 = "p1"
    P2 = "p2"
    NONE = "none"


class MoscaZBasis(_CanonicalEnum):
    """Where the threat horizon Z came from. A Z without its basis is unusable."""

    ORG_HORIZON = "org_horizon"
    RESOURCE_MODEL = "resource_model"
    UNAVAILABLE = "unavailable"


class QuantumProjectionStatus(_CanonicalEnum):
    CALCULATED = "calculated"
    BEYOND_HORIZON = "beyond_horizon"
    MODEL_UNAVAILABLE = "model_unavailable"
    NOT_REQUIRED = "not_required"


class ResourceScenario(_CanonicalEnum):
    """Scales the capability curve P(t) -- never the attack requirement Q."""

    CONSERVATIVE = "conservative"
    BASELINE = "baseline"
    AGGRESSIVE = "aggressive"


class EvidenceSource(_CanonicalEnum):
    """Ranked sources for the confidentiality lifetime X."""

    USER = "user"
    SCANNER = "scanner"
    ORG_POLICY = "org_policy"
    LEGAL_PROFILE = "legal_profile"


class RetentionBasis(_CanonicalEnum):
    """What backs a retention figure.

    ``regulatory_minimum`` carries an explicit caveat: Indian statutes mandate
    retention *minimums*, not confidentiality lifetimes, and the two are not
    interchangeable.
    """

    LEGAL = "legal"
    REGULATORY_MINIMUM = "regulatory_minimum"
    ASSUMPTION = "assumption"


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------


class ScannerKind(_CanonicalEnum):
    SOURCE = "source"
    CONTAINER = "container"
    CLOUD_HSM = "cloud_hsm"
    NETWORK = "network"
    BINARY = "binary"


class ScanTargetKind(_CanonicalEnum):
    GIT_REPOSITORY = "git_repository"
    LOCAL_PATH = "local_path"
    CONTAINER_IMAGE = "container_image"
    BINARY_FILE = "binary_file"
    NETWORK_ENDPOINT = "network_endpoint"
    CLOUD_ACCOUNT = "cloud_account"


class ScanStatus(_CanonicalEnum):
    """A scan must always reach a terminal state.

    ``RUNNING`` that never ends is the failure mode with no user-visible end, so
    the worker guarantees a transition to ``FAILED`` on any unhandled error.
    """

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL_SCAN_STATUSES


_TERMINAL_SCAN_STATUSES = frozenset(
    {
        ScanStatus.SUCCEEDED,
        ScanStatus.PARTIAL,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
    }
)


class DependencyRelation(_CanonicalEnum):
    """Edge kinds in the artefact dependency graph (1.10)."""

    DEPENDS_ON = "depends_on"
    PROVIDES = "provides"
    USES = "uses"
    CONTAINS = "contains"
    SIGNED_BY = "signed_by"
    ISSUED_BY = "issued_by"
    PROTECTS = "protects"


class UserRole(_CanonicalEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


__all__ = [
    "AssessmentStatus",
    "AssetType",
    "BusinessCriticality",
    "CipherMode",
    "CloudProvider",
    "CloudServiceKind",
    "Confidence",
    "DataClassification",
    "DependencyRelation",
    "DetectionMethod",
    "EvidenceSource",
    "ExposureLevel",
    "FipsStatus",
    "KeyManagementKind",
    "KeyState",
    "KeyStorageLocation",
    "MoscaZBasis",
    "NistSecurityLevel",
    "Padding",
    "Primitive",
    "Priority",
    "ProtocolName",
    "ProvenanceTier",
    "Purpose",
    "QuantumProjectionStatus",
    "QuantumVulnerability",
    "ResourceScenario",
    "RetentionBasis",
    "ScanStatus",
    "ScanTargetKind",
    "ScannerKind",
    "UserRole",
]
