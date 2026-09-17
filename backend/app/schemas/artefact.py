"""The canonical artefact schemas (plan tasks 1.2 - 1.8).

One base record, :class:`CryptoArtefact`, carries what every cryptographic asset
has. Seven typed detail models carry what only some have, attached through the
``detail`` discriminated union so that a certificate's ``not_after`` cannot be
set on a library and a key size cannot be invented for a package name.

The central design rule throughout is **P3**: every field that a scanner might
fail to observe is ``| None``, and ``None`` means *not observed*. No field is
given a midpoint or a plausible default, because a silent default is
indistinguishable from a measurement.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from app.models.enums import (
    AssetType,
    CipherMode,
    CloudProvider,
    CloudServiceKind,
    Confidence,
    FipsStatus,
    KeyManagementKind,
    KeyState,
    KeyStorageLocation,
    NistSecurityLevel,
    Padding,
    Primitive,
    ProtocolName,
    Purpose,
    QuantumVulnerability,
    ScannerKind,
)
from app.schemas.common import Evidence, TrinetraModel, compute_artefact_id

# ---------------------------------------------------------------------------
# 1.3  Key material
# ---------------------------------------------------------------------------


class KeyDetail(TrinetraModel):
    """Detail for ``asset_type == key`` (plan task 1.3)."""

    detail_type: Literal[AssetType.KEY] = AssetType.KEY

    key_type: str | None = Field(
        default=None, description="e.g. rsa, ec, aes, hmac. None when unobserved."
    )
    size_bits: int | None = Field(default=None, gt=0)
    state: KeyState = KeyState.UNKNOWN
    storage_location: KeyStorageLocation = KeyStorageLocation.UNKNOWN

    created_at: datetime | None = None
    activated_at: datetime | None = None
    expires_at: datetime | None = None
    rotation_period_days: int | None = Field(
        default=None,
        gt=0,
        description="Observed or configured rotation period. None means no "
        "rotation policy was found -- which is itself a finding, and must not "
        "be reported as 'rotates yearly'.",
    )

    is_hardcoded: bool = Field(
        default=False,
        description="Key material embedded in source, config or an image layer. "
        "Always a finding regardless of algorithm strength.",
    )
    is_exposed: bool = Field(
        default=False,
        description="Reachable by a party that should not hold it, e.g. a key in "
        "a public repository or a world-readable file.",
    )
    fingerprint_sha256: str | None = Field(
        default=None,
        description="Hash of the public key or key identifier. Never the key "
        "itself -- Trinetra stores no secret material.",
    )

    @model_validator(mode="after")
    def _check_lifecycle_order(self) -> Self:
        if (
            self.created_at is not None
            and self.expires_at is not None
            and self.expires_at < self.created_at
        ):
            raise ValueError("key expires_at precedes created_at")
        return self


# ---------------------------------------------------------------------------
# 1.4  Certificates
# ---------------------------------------------------------------------------


class CertificateDetail(TrinetraModel):
    """Detail for ``asset_type == certificate`` (plan task 1.4)."""

    detail_type: Literal[AssetType.CERTIFICATE] = AssetType.CERTIFICATE

    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None

    not_before: datetime | None = None
    not_after: datetime | None = None

    signature_algorithm: str | None = Field(
        default=None,
        description="Algorithm the ISSUER used to sign. Distinct from the "
        "subject public key: a quantum-vulnerable signature on a certificate is "
        "an authenticity risk, while a vulnerable public key is a "
        "confidentiality one.",
    )
    public_key_algorithm: str | None = None
    public_key_size_bits: int | None = Field(default=None, gt=0)
    public_key_curve: str | None = None

    subject_alternative_names: list[str] = Field(default_factory=list)
    is_self_signed: bool | None = None
    is_ca: bool | None = None
    chain_depth: int | None = Field(default=None, ge=0)
    fingerprint_sha256: str | None = None

    @model_validator(mode="after")
    def _check_validity_window(self) -> Self:
        if (
            self.not_before is not None
            and self.not_after is not None
            and self.not_after < self.not_before
        ):
            raise ValueError("certificate not_after precedes not_before")
        return self

    def is_expired_at(self, moment: datetime) -> bool | None:
        """Whether the certificate is expired at ``moment``.

        Returns ``None`` rather than ``False`` when ``not_after`` was never
        observed: "we did not read an expiry" is not "it has not expired" (P3).
        """
        if self.not_after is None:
            return None
        return self.not_after < moment


# ---------------------------------------------------------------------------
# 1.5  Protocols
# ---------------------------------------------------------------------------


class ProtocolDetail(TrinetraModel):
    """Detail for ``asset_type == protocol`` (plan task 1.5)."""

    detail_type: Literal[AssetType.PROTOCOL] = AssetType.PROTOCOL

    protocol: ProtocolName = ProtocolName.OTHER
    version: str | None = Field(
        default=None, description="e.g. '1.2', '1.3', '2.0'. None when unobserved."
    )
    cipher_suites: list[str] = Field(default_factory=list)
    key_exchange_groups: list[str] = Field(default_factory=list)
    signature_algorithms: list[str] = Field(default_factory=list)

    is_observed: bool = Field(
        default=False,
        description="True when read from a live handshake, false when declared "
        "in configuration. Declared and observed crypto routinely differ, and "
        "the distinction must survive to the UI.",
    )
    supports_hybrid_kex: bool | None = Field(
        default=None,
        description="Whether a PQC hybrid group such as X25519MLKEM768 is "
        "offered. None means not determined.",
    )


# ---------------------------------------------------------------------------
# 1.6  Libraries
# ---------------------------------------------------------------------------


class LibraryDetail(TrinetraModel):
    """Detail for ``asset_type == library`` (plan task 1.6).

    A library finding proves that a crypto implementation is present. It does
    **not** prove any particular algorithm is used, which is why
    :attr:`CryptoArtefact.algorithm` is forced empty for libraries.
    """

    detail_type: Literal[AssetType.LIBRARY] = AssetType.LIBRARY

    package_name: str
    version: str | None = None
    purl: str | None = Field(
        default=None, description="Package URL, e.g. pkg:golang/crypto@0.17.0"
    )
    ecosystem: str | None = Field(default=None, description="npm, pypi, maven, ...")
    fips_status: FipsStatus = FipsStatus.UNKNOWN
    supports_pqc: bool | None = Field(
        default=None,
        description="Whether this version ships PQC primitives. None means the "
        "knowledge base has no entry -- not that it lacks support.",
    )
    is_direct_dependency: bool | None = None


# ---------------------------------------------------------------------------
# 1.7  Hardware modules
# ---------------------------------------------------------------------------


class HardwareModuleDetail(TrinetraModel):
    """Detail for ``asset_type == hardware_module`` (plan task 1.7)."""

    detail_type: Literal[AssetType.HARDWARE_MODULE] = AssetType.HARDWARE_MODULE

    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    serial_number: str | None = None

    pkcs11_slot_id: int | None = Field(default=None, ge=0)
    pkcs11_token_label: str | None = None

    fips_status: FipsStatus = FipsStatus.UNKNOWN
    fips_certificate_number: str | None = None

    supports_pqc: bool | None = Field(
        default=None,
        description="PQC-capable firmware. Load-bearing for migration planning: "
        "an HSM that cannot be upgraded is a hardware purchase, not a code "
        "change, and dominates the cost model.",
    )


# ---------------------------------------------------------------------------
# 1.8  Cloud services
# ---------------------------------------------------------------------------


class CloudServiceDetail(TrinetraModel):
    """Detail for ``asset_type == cloud_service`` (plan task 1.8)."""

    detail_type: Literal[AssetType.CLOUD_SERVICE] = AssetType.CLOUD_SERVICE

    provider: CloudProvider = CloudProvider.OTHER
    service: CloudServiceKind = CloudServiceKind.OTHER
    resource_id: str | None = Field(
        default=None, description="ARN, resource URI or key id."
    )
    region: str | None = None
    key_spec: str | None = Field(
        default=None, description="Provider key spec, e.g. RSA_2048, SYMMETRIC_DEFAULT."
    )
    key_management: KeyManagementKind = KeyManagementKind.UNKNOWN
    rotation_enabled: bool | None = None
    fips_status: FipsStatus = FipsStatus.UNKNOWN


# ---------------------------------------------------------------------------
# Algorithm and generic material
# ---------------------------------------------------------------------------


class AlgorithmDetail(TrinetraModel):
    """Detail for ``asset_type == algorithm`` (the R19 fields).

    ``AES`` is not an answer; ``AES-256-GCM`` is. Each of these fields is
    ``None`` when the call site did not state it -- ``AES.new(key, MODE_GCM)``
    genuinely does not reveal the key size, and the finding must say so rather
    than assume 128 or 256.
    """

    detail_type: Literal[AssetType.ALGORITHM] = AssetType.ALGORITHM

    mode: CipherMode | None = None
    padding: Padding | None = None
    key_size_bits: int | None = Field(default=None, gt=0)
    curve: str | None = Field(default=None, description="e.g. P-256, Curve25519.")
    parameter_set: str | None = Field(
        default=None,
        description="CycloneDX parameterSetIdentifier, e.g. '2048' or 'ML-KEM-768'.",
    )
    rounds: int | None = Field(default=None, gt=0)


class RelatedMaterialDetail(TrinetraModel):
    """Detail for ``asset_type == related_material``: salts, IVs, nonces, seeds."""

    detail_type: Literal[AssetType.RELATED_MATERIAL] = AssetType.RELATED_MATERIAL

    material_kind: str | None = Field(
        default=None, description="iv, nonce, salt, seed, token, ..."
    )
    size_bits: int | None = Field(default=None, gt=0)
    is_hardcoded: bool = Field(
        default=False,
        description="A static IV or salt defeats the construction it feeds, so "
        "this is a finding independent of the algorithm's strength.",
    )


ArtefactDetail = Annotated[
    AlgorithmDetail
    | KeyDetail
    | CertificateDetail
    | ProtocolDetail
    | LibraryDetail
    | HardwareModuleDetail
    | CloudServiceDetail
    | RelatedMaterialDetail,
    Field(discriminator="detail_type"),
]


# ---------------------------------------------------------------------------
# 1.2  The core record
# ---------------------------------------------------------------------------


class CryptoArtefact(TrinetraModel):
    """One cryptographic asset, however it was discovered (plan task 1.2).

    This is the single record every scanner produces and every engine consumes.
    Whatever found it -- Semgrep, Syft, a TLS handshake, a PKCS#11 enumeration --
    a finding arrives here and nothing downstream can tell the difference.
    """

    artefact_id: str = Field(
        description="Deterministic sha256 identity; stable across rescans of the "
        "same target. Produced by from_evidence()."
    )
    scan_id: str | None = Field(
        default=None, description="Owning scan. None before persistence."
    )

    asset_type: AssetType
    name: str = Field(
        min_length=1,
        description="As discovered, e.g. 'RSA-2048', 'OpenSSL', 'TLS 1.2'.",
    )
    algorithm: str | None = Field(
        default=None,
        description="Normalised algorithm name. **Always None for libraries** -- "
        "see the model validator; a package name is not an algorithm.",
    )
    oid: str | None = Field(default=None, description="ASN.1 OID where applicable.")

    primitive: Primitive | None = None
    purposes: list[Purpose] = Field(default_factory=list)

    quantum_vulnerability: QuantumVulnerability = QuantumVulnerability.UNKNOWN
    nist_security_level: NistSecurityLevel = NistSecurityLevel.UNKNOWN

    detail: ArtefactDetail | None = Field(
        default=None, description="Type-specific fields; see the detail models."
    )

    evidence: list[Evidence] = Field(
        min_length=1,
        description="At least one. An artefact with no evidence is a bug (P3).",
    )
    discovered_by: ScannerKind

    first_seen: datetime
    last_seen: datetime

    raw_cbom: dict | None = Field(
        default=None,
        description="The original CycloneDX component. Nothing a scanner "
        "produced is ever lost, even if Trinetra does not model it yet.",
    )

    @model_validator(mode="after")
    def _library_findings_carry_no_algorithm(self) -> Self:
        """Enforce the rule that keeps the risk engine honest.

        *OpenSSL is installed* proves a crypto implementation exists, not that
        any particular algorithm is used. Leaving ``algorithm`` populated here
        would let the risk engine manufacture an attack model out of a package
        name.
        """
        if self.asset_type is AssetType.LIBRARY and self.algorithm is not None:
            raise ValueError(
                "library artefacts must not carry an algorithm: a package name "
                "is dependency evidence, not an algorithm in use"
            )
        return self

    @model_validator(mode="after")
    def _detail_matches_asset_type(self) -> Self:
        if self.detail is not None and self.detail.detail_type != self.asset_type:
            raise ValueError(
                f"detail type {self.detail.detail_type.value!r} does not match "
                f"asset_type {self.asset_type.value!r}"
            )
        return self

    @model_validator(mode="after")
    def _seen_window_is_ordered(self) -> Self:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen precedes first_seen")
        return self

    # -- construction ------------------------------------------------------

    @classmethod
    def from_evidence(
        cls,
        *,
        scan_target: str,
        asset_type: AssetType,
        name: str,
        evidence: list[Evidence],
        discovered_by: ScannerKind,
        observed_at: datetime,
        discriminator: str | None = None,
        **fields: object,
    ) -> CryptoArtefact:
        """Build an artefact, deriving its deterministic id from its evidence.

        This is the only supported way for a scanner adapter to create an
        artefact: it guarantees the id is computed consistently, so the same
        finding in a later scan keeps its identity.
        """
        if not evidence:
            raise ValueError("an artefact requires at least one piece of evidence")

        primary = evidence[0].location
        artefact_id = compute_artefact_id(
            scan_target=scan_target,
            asset_type=asset_type.value,
            name=name,
            location_path=primary.path,
            location_line=primary.line,
            discriminator=discriminator,
        )
        return cls(
            artefact_id=artefact_id,
            asset_type=asset_type,
            name=name,
            evidence=evidence,
            discovered_by=discovered_by,
            first_seen=observed_at,
            last_seen=observed_at,
            **fields,  # type: ignore[arg-type]
        )

    # -- derived properties -------------------------------------------------

    @property
    def confidence(self) -> Confidence:
        """Strongest confidence among this artefact's evidence.

        Two independent medium-confidence detections of the same asset do not
        make it high confidence, but the best single piece of evidence is the
        fairest summary of what is known.
        """
        return min((e.confidence for e in self.evidence), key=lambda c: c.rank)

    @property
    def is_quantum_vulnerable(self) -> bool:
        """Whether a CRQC materially weakens this artefact.

        ``UNKNOWN`` returns ``False`` -- it must never be presented as a
        confirmed vulnerability. Unassessed artefacts are surfaced through
        ``AssessmentStatus.NEEDS_CONTEXT``, not by inflating this flag.
        """
        return self.quantum_vulnerability in {
            QuantumVulnerability.SHOR_BROKEN,
            QuantumVulnerability.GROVER_WEAKENED,
        }

    @property
    def primary_location(self) -> str:
        return self.evidence[0].location.render()

    def merged_with(self, other: CryptoArtefact) -> CryptoArtefact:
        """Combine a rediscovery of the same artefact with this one.

        Widens the ``first_seen``/``last_seen`` window and unions the evidence,
        so that re-scanning enriches an artefact rather than duplicating it.
        """
        if other.artefact_id != self.artefact_id:
            raise ValueError("cannot merge artefacts with different identities")

        seen: set[tuple] = set()
        combined: list[Evidence] = []
        for item in [*self.evidence, *other.evidence]:
            key = (
                item.location.path,
                item.location.line,
                item.detection_method,
                item.rule_id,
            )
            if key not in seen:
                seen.add(key)
                combined.append(item)

        return self.model_copy(
            update={
                "evidence": combined,
                "first_seen": min(self.first_seen, other.first_seen),
                "last_seen": max(self.last_seen, other.last_seen),
            }
        )


__all__ = [
    "AlgorithmDetail",
    "ArtefactDetail",
    "CertificateDetail",
    "CloudServiceDetail",
    "CryptoArtefact",
    "HardwareModuleDetail",
    "KeyDetail",
    "LibraryDetail",
    "ProtocolDetail",
    "RelatedMaterialDetail",
]
