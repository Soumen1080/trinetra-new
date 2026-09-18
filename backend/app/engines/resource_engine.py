"""Track B: project when an attack's stated logical resources may be available."""

from __future__ import annotations

import re

from app.engines.profiles.loader import AttackModel, QuantumCapabilityProfile
from app.models.enums import (
    Confidence,
    QuantumProjectionStatus,
    QuantumVulnerability,
    ResourceScenario,
)
from app.schemas.artefact import CryptoArtefact
from app.schemas.risk import ResourceTrack


def normalise_algorithm(value: str | None) -> str | None:
    """Map scanner spellings to the profile's stable algorithm keys."""
    if not value:
        return None
    compact = re.sub(r"[^a-z0-9]", "", value.lower())
    if compact.startswith("rsa"):
        return "rsa"
    if compact in {"x25519", "curve25519"}:
        return "x25519"
    if compact == "ed25519":
        return "ed25519"
    if compact.startswith("ecdh"):
        return "ecdh"
    if compact.startswith("ecdsa"):
        return "ecdsa"
    if compact.startswith("ec") or compact.startswith("ecc"):
        return "ecc"
    return compact or None


def key_size_bits(artefact: CryptoArtefact) -> int | None:
    """Read a key size without manufacturing one when the scanner omitted it."""
    detail = artefact.detail
    for field in ("key_size_bits", "size_bits", "public_key_size_bits"):
        value = getattr(detail, field, None)
        if isinstance(value, int):
            return value

    for value in (artefact.name, artefact.algorithm or ""):
        match = re.search(r"(?:p[-_ ]?)?(\d{3,5})", value.lower())
        if match:
            return int(match.group(1))
    algorithm = normalise_algorithm(artefact.algorithm or artefact.name)
    if algorithm in {"x25519", "ed25519"}:
        return 255
    return None


def _find_attack_model(
    artefact: CryptoArtefact, profile: QuantumCapabilityProfile
) -> AttackModel | None:
    algorithm = normalise_algorithm(artefact.algorithm or artefact.name)
    size = key_size_bits(artefact)
    if algorithm is None or size is None:
        return None
    candidates = [algorithm]
    if algorithm in {"ecdh", "ecdsa", "x25519", "ed25519"}:
        candidates.append("ecc")
    for candidate in candidates:
        for model in profile.attack_models:
            if model.algorithm == candidate and model.key_size_bits == size:
                return model
    return None


def _point_confidence(value: str) -> Confidence:
    return Confidence.LOW if value == "low" else Confidence.MEDIUM


def evaluate_resources(
    artefact: CryptoArtefact,
    profile: QuantumCapabilityProfile,
    *,
    scenario: ResourceScenario = ResourceScenario.BASELINE,
) -> ResourceTrack:
    """Return Track B using a profile's fixed Q and P(t) values.

    The scenario multiplier is applied to capability *only*.  Q is copied from
    the cited attack model unchanged, so an optimistic roadmap can never make
    RSA itself appear easier to factor.
    """
    if artefact.quantum_vulnerability in {
        QuantumVulnerability.QUANTUM_SAFE,
        QuantumVulnerability.NOT_APPLICABLE,
    }:
        return ResourceTrack(
            scenario=scenario,
            status=QuantumProjectionStatus.NOT_REQUIRED,
            caveats=["The artefact is marked quantum-safe or not applicable."],
        )

    model = _find_attack_model(artefact, profile)
    if model is None:
        return ResourceTrack(
            scenario=scenario,
            status=QuantumProjectionStatus.MODEL_UNAVAILABLE,
            caveats=[
                "No cited logical-resource model matches the observed algorithm "
                "and key size."
            ],
        )

    scale = profile.scenarios[scenario.value]
    shared = {
        "scenario_multiplier": str(scale),
        "construction": model.construction,
        "source_id": model.source_id,
        **model.assumptions,
    }
    last_complete_point = None
    for point in profile.capability_curve:
        # A point that only supplies one dimension is evidence about neither a
        # complete attack nor a crossing.  Do not interpolate it into an answer.
        if point.logical_qubits is None or point.logical_gates is None:
            continue
        last_complete_point = point
        scaled_qubits = point.logical_qubits * scale
        scaled_gates = point.logical_gates * scale
        if scaled_qubits < model.logical_qubits or scaled_gates < model.logical_gates:
            continue
        capability = {
            "year": point.year,
            "logical_qubits": scaled_qubits,
            "logical_gates": scaled_gates,
            "confidence": point.confidence,
            "basis": point.basis,
        }
        return ResourceTrack(
            m_years=float(point.year - profile.reference_year),
            scenario=scenario,
            status=QuantumProjectionStatus.CALCULATED,
            projected_break_year=point.year,
            migration_deadline_year=point.year,
            logical_qubits_required=model.logical_qubits,
            gate_count_required=float(model.logical_gates),
            assumptions=shared,
            caveats=model.caveats,
            confidence=_point_confidence(point.confidence),
            forecast_capability=capability,
        )

    horizon_capability: dict[str, int | float | str | None] = {}
    if last_complete_point is not None:
        horizon_capability = {
            "year": last_complete_point.year,
            "logical_qubits": last_complete_point.logical_qubits * scale,
            "logical_gates": last_complete_point.logical_gates * scale,
            "confidence": last_complete_point.confidence,
            "basis": last_complete_point.basis,
        }
    return ResourceTrack(
        scenario=scenario,
        status=QuantumProjectionStatus.BEYOND_HORIZON,
        logical_qubits_required=model.logical_qubits,
        gate_count_required=float(model.logical_gates),
        assumptions=shared,
        caveats=[*model.caveats, "No complete capability point met both Q dimensions."],
        confidence=Confidence.LOW,
        forecast_capability=horizon_capability,
    )


__all__ = ["evaluate_resources", "key_size_bits", "normalise_algorithm"]
