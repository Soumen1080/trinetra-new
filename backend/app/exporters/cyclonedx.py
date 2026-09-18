"""CycloneDX 1.6 CBOM export (plan task 7.1).

Builds a complete CycloneDX 1.6 BOM document from a ``ScanResult`` with
enriched risk and recommendation data.  Every ``CryptoArtefact`` becomes a
CycloneDX component with full ``cryptoProperties``: ``assetType``,
``algorithmProperties``, ``certificateProperties``,
``relatedCryptoMaterialProperties``, ``protocolProperties``, ``evidence``
and ``occurrences``.

The output **must** validate against the official CycloneDX 1.6 JSON schema.
This is the Phase 7 exit criterion and is enforced in
``test_phase7_exporters.py``.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from app.models.enums import AssetType, Priority
from app.schemas.artefact import (
    AlgorithmDetail,
    CertificateDetail,
    CloudServiceDetail,
    CryptoArtefact,
    HardwareModuleDetail,
    KeyDetail,
    LibraryDetail,
    ProtocolDetail,
    RelatedMaterialDetail,
)
from app.schemas.recommendation import PqcRecommendation
from app.schemas.risk import RiskAssessment
from app.schemas.scan import ScanResult
from app.schemas.vocab import (
    TRINETRA_ASSET_TYPE_PROPERTY,
    asset_type_needs_hint,
    asset_type_to_cyclonedx,
    mode_to_cyclonedx,
    padding_to_cyclonedx,
    primitive_to_cyclonedx,
    purpose_to_cyclonedx,
)

#: CycloneDX specification version this exporter targets.
SPEC_VERSION = "1.6"

#: BOM format identifier.
BOM_FORMAT = "CycloneDX"

TRINETRA_TOOL_NAME = "trinetra"
TRINETRA_TOOL_VENDOR = "Trinetra Project"


def export_cyclonedx(
    scan_result: ScanResult,
    assessments: list[RiskAssessment] | None = None,
    recommendations: list[PqcRecommendation] | None = None,
) -> str:
    """Export a scan result as a CycloneDX 1.6 CBOM JSON string."""
    assessments = assessments or []
    recommendations = recommendations or []

    assessment_by_artefact = {a.artefact_id: a for a in assessments}
    recommendation_by_assessment = {r.assessment_id: r for r in recommendations}

    bom = _build_bom_envelope(scan_result)
    components: list[dict[str, Any]] = []

    for artefact in scan_result.deduplicated():
        assessment = assessment_by_artefact.get(artefact.artefact_id)
        rec = (
            recommendation_by_assessment.get(assessment.assessment_id)
            if assessment
            else None
        )
        components.append(_artefact_to_component(artefact, assessment, rec))

    bom["components"] = components
    return json.dumps(bom, indent=2, sort_keys=False, default=str)


# ---------------------------------------------------------------------------
# BOM envelope
# ---------------------------------------------------------------------------


def _build_bom_envelope(scan_result: ScanResult) -> dict[str, Any]:
    """Build the top-level BOM structure."""
    now = datetime.now(UTC).isoformat()
    serial = f"urn:uuid:{uuid.uuid4()}"

    metadata: dict[str, Any] = {
        "timestamp": now,
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": TRINETRA_TOOL_NAME,
                    "vendor": TRINETRA_TOOL_VENDOR,
                    "version": scan_result.schema_version,
                }
            ],
        },
        "component": {
            "type": "application",
            "name": scan_result.target.display_name
            or scan_result.target.identifier,
            "bom-ref": f"target-{scan_result.scan_id}",
        },
    }

    # Add scanner tool versions
    for tool in scan_result.tool_versions:
        metadata["tools"]["components"].append(
            {
                "type": "application",
                "name": tool.name,
                "version": tool.version,
            }
        )

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": metadata,
    }


# ---------------------------------------------------------------------------
# Component mapping
# ---------------------------------------------------------------------------


def _artefact_to_component(
    artefact: CryptoArtefact,
    assessment: RiskAssessment | None,
    recommendation: PqcRecommendation | None,
) -> dict[str, Any]:
    """Map a single artefact to a CycloneDX component."""
    component: dict[str, Any] = {
        "type": "cryptographic-asset",
        "name": artefact.name,
        "bom-ref": artefact.artefact_id,
    }

    # cryptoProperties
    crypto: dict[str, Any] = {
        "assetType": asset_type_to_cyclonedx(artefact.asset_type),
    }

    # OID
    if artefact.oid:
        crypto["oid"] = artefact.oid

    # Algorithm properties
    algo_props = _build_algorithm_properties(artefact)
    if algo_props:
        crypto["algorithmProperties"] = algo_props

    # Certificate properties
    cert_props = _build_certificate_properties(artefact)
    if cert_props:
        crypto["certificateProperties"] = cert_props

    # Related crypto material properties
    material_props = _build_related_material_properties(artefact)
    if material_props:
        crypto["relatedCryptoMaterialProperties"] = material_props

    # Protocol properties
    proto_props = _build_protocol_properties(artefact)
    if proto_props:
        crypto["protocolProperties"] = proto_props

    component["cryptoProperties"] = crypto

    # Evidence / occurrences
    occurrences = _build_occurrences(artefact)
    if occurrences:
        component["evidence"] = {"occurrences": occurrences}

    # Extension properties — Trinetra-specific data that CycloneDX cannot
    # represent natively.
    properties: list[dict[str, str]] = []

    if asset_type_needs_hint(artefact.asset_type):
        properties.append(
            {
                "name": TRINETRA_ASSET_TYPE_PROPERTY,
                "value": artefact.asset_type.value,
            }
        )

    if artefact.algorithm:
        properties.append(
            {"name": "trinetra:algorithm", "value": artefact.algorithm}
        )

    properties.append(
        {
            "name": "trinetra:quantum-vulnerability",
            "value": artefact.quantum_vulnerability.value,
        }
    )

    if assessment:
        if assessment.final_score is not None:
            properties.append(
                {
                    "name": "trinetra:risk-score",
                    "value": str(assessment.final_score),
                }
            )
        properties.append(
            {"name": "trinetra:priority", "value": assessment.priority.value}
        )
        if assessment.mosca.is_urgent is not None:
            properties.append(
                {
                    "name": "trinetra:mosca-urgent",
                    "value": str(assessment.mosca.is_urgent).lower(),
                }
            )

    if recommendation and recommendation.recommended_algorithm:
        properties.append(
            {
                "name": "trinetra:recommended-algorithm",
                "value": recommendation.recommended_algorithm,
            }
        )

    if properties:
        component["properties"] = properties

    return component


# ---------------------------------------------------------------------------
# cryptoProperties builders
# ---------------------------------------------------------------------------


def _build_algorithm_properties(
    artefact: CryptoArtefact,
) -> dict[str, Any] | None:
    """Build ``algorithmProperties`` for algorithm and related asset types."""
    props: dict[str, Any] = {}

    # Primitive
    if artefact.primitive:
        props["primitive"] = primitive_to_cyclonedx(artefact.primitive)

    # Crypto functions (purposes)
    if artefact.purposes:
        props["cryptoFunctions"] = [
            purpose_to_cyclonedx(p) for p in artefact.purposes
        ]

    detail = artefact.detail

    if isinstance(detail, AlgorithmDetail):
        if detail.parameter_set:
            props["parameterSetIdentifier"] = detail.parameter_set
        if detail.curve:
            props["curve"] = detail.curve
        if detail.mode:
            props["mode"] = mode_to_cyclonedx(detail.mode)
        if detail.padding:
            props["padding"] = padding_to_cyclonedx(detail.padding)
        if detail.key_size_bits:
            props["parameterSetIdentifier"] = props.get(
                "parameterSetIdentifier", str(detail.key_size_bits)
            )

    # executionEnvironment — populated from cloud service context
    if isinstance(detail, CloudServiceDetail):
        props["executionEnvironment"] = (
            f"{detail.provider.value}:{detail.service.value}"
        )

    # certificationLevel — from FIPS status
    fips = getattr(detail, "fips_status", None)
    if fips and hasattr(fips, "value") and fips.value != "unknown":
        props["certificationLevel"] = [fips.value.upper().replace("_", "-")]

    return props or None


def _build_certificate_properties(
    artefact: CryptoArtefact,
) -> dict[str, Any] | None:
    """Build ``certificateProperties`` for certificate artefacts."""
    detail = artefact.detail
    if not isinstance(detail, CertificateDetail):
        return None

    props: dict[str, Any] = {}

    if detail.subject:
        props["subjectName"] = detail.subject
    if detail.issuer:
        props["issuerName"] = detail.issuer
    if detail.not_before:
        props["notBefore"] = detail.not_before.isoformat()
    if detail.not_after:
        props["notAfter"] = detail.not_after.isoformat()
    if detail.signature_algorithm:
        props["signatureAlgorithmRef"] = detail.signature_algorithm
    if detail.subject_alternative_names:
        props["subjectAlternativeNames"] = detail.subject_alternative_names
    if detail.serial_number:
        props["certificateFormat"] = "X.509"
    if detail.fingerprint_sha256:
        props["certificateExtension"] = detail.fingerprint_sha256

    return props or None


def _build_related_material_properties(
    artefact: CryptoArtefact,
) -> dict[str, Any] | None:
    """Build ``relatedCryptoMaterialProperties`` for keys, HW modules, cloud."""
    detail = artefact.detail
    props: dict[str, Any] = {}

    if isinstance(detail, KeyDetail):
        if detail.key_type:
            props["type"] = detail.key_type
        if detail.size_bits:
            props["size"] = detail.size_bits
        if detail.state and detail.state.value != "unknown":
            props["state"] = detail.state.value
        if detail.created_at:
            props["creationDate"] = detail.created_at.isoformat()
        if detail.activated_at:
            props["activationDate"] = detail.activated_at.isoformat()
        if detail.expires_at:
            props["expirationDate"] = detail.expires_at.isoformat()
        if detail.fingerprint_sha256:
            props["id"] = detail.fingerprint_sha256

    elif isinstance(detail, HardwareModuleDetail):
        props["type"] = "hardware-module"
        if detail.vendor:
            props["id"] = f"{detail.vendor}:{detail.model or 'unknown'}"

    elif isinstance(detail, CloudServiceDetail):
        props["type"] = "cloud-service"
        if detail.resource_id:
            props["id"] = detail.resource_id

    elif isinstance(detail, RelatedMaterialDetail):
        if detail.material_kind:
            props["type"] = detail.material_kind
        if detail.size_bits:
            props["size"] = detail.size_bits

    return props or None


def _build_protocol_properties(
    artefact: CryptoArtefact,
) -> dict[str, Any] | None:
    """Build ``protocolProperties`` for protocol artefacts."""
    detail = artefact.detail
    if not isinstance(detail, ProtocolDetail):
        return None

    props: dict[str, Any] = {
        "type": detail.protocol.value,
    }

    if detail.version:
        props["version"] = detail.version

    if detail.cipher_suites:
        props["cipherSuites"] = {
            "identifiers": detail.cipher_suites,
        }

    return props


# ---------------------------------------------------------------------------
# Evidence / occurrences
# ---------------------------------------------------------------------------


def _build_occurrences(artefact: CryptoArtefact) -> list[dict[str, Any]]:
    """Build the ``evidence.occurrences`` array from artefact evidence."""
    occurrences: list[dict[str, Any]] = []
    for ev in artefact.evidence:
        loc = ev.location
        occ: dict[str, Any] = {"location": loc.path}
        if loc.line is not None:
            occ["line"] = loc.line
        if loc.column is not None:
            occ["offset"] = loc.column
        if loc.symbol:
            occ["symbol"] = loc.symbol
        if ev.snippet and not ev.redacted:
            occ["additionalContext"] = ev.snippet
        occurrences.append(occ)
    return occurrences


__all__ = ["export_cyclonedx"]
