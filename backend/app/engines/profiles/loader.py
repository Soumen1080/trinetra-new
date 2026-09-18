"""Load profile JSON once and reject malformed policy before scoring begins.

The profiles are deliberately local, versioned JSON rather than database rows.
They can therefore be code-reviewed alongside the engine that consumes them and
an old assessment can always name the exact policy that produced it.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError, field_validator, model_validator

from app.schemas.common import TrinetraModel
from app.schemas.risk import FACTOR_WEIGHTS


class ProfileError(ValueError):
    """A profile cannot safely be used by a scoring engine."""


class ProfileSource(TrinetraModel):
    source_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    url: str = Field(min_length=1)
    citation: str = Field(min_length=1)


class RetentionCategory(TrinetraModel):
    lifetime_years: int = Field(ge=0)
    basis: Literal["legal", "regulatory_minimum", "assumption"]
    source_id: str = Field(min_length=1)
    sensitivity: Literal["restricted", "confidential", "internal", "public"]
    caveat: str | None = None

    @model_validator(mode="after")
    def _minimums_keep_their_caveat(self) -> RetentionCategory:
        if self.basis == "regulatory_minimum" and not self.caveat:
            raise ValueError("regulatory_minimum categories require a caveat")
        return self


class RetentionProfile(TrinetraModel):
    profile_type: Literal["retention_policy"]
    version: str = Field(pattern=r"^retention-policy-\d{4}\.\d+$")
    warning: str = Field(min_length=1)
    sources: list[ProfileSource] = Field(min_length=1)
    categories: dict[str, RetentionCategory] = Field(min_length=10)

    @model_validator(mode="after")
    def _categories_reference_sources(self) -> RetentionProfile:
        source_ids = {source.source_id for source in self.sources}
        unknown = sorted(
            category.source_id
            for category in self.categories.values()
            if category.source_id not in source_ids
        )
        if unknown:
            raise ValueError(f"categories reference unknown sources: {unknown}")
        required_warning = (
            "Indian statutes mandate retention minimums, not confidentiality lifetimes."
        )
        normalised = self.warning.replace("*", "")
        if required_warning.lower() not in normalised.lower():
            raise ValueError("retention profile must carry the Indian-retention warning")
        for name in ("biometric", "credential_secret"):
            category = self.categories.get(name)
            if category is None or category.basis != "assumption":
                raise ValueError(f"{name} must be an explicitly labelled assumption")
        return self


class AttackModel(TrinetraModel):
    algorithm: str = Field(min_length=1)
    key_size_bits: int = Field(gt=0)
    logical_qubits: int = Field(gt=0)
    logical_gates: int = Field(gt=0)
    construction: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    assumptions: dict[str, str] = Field(min_length=3)
    caveats: list[str] = Field(min_length=1)


class CapabilityPoint(TrinetraModel):
    year: int = Field(ge=2026, le=2100)
    logical_qubits: int | None = Field(default=None, gt=0)
    logical_gates: int | None = Field(default=None, gt=0)
    confidence: Literal["roadmap", "moderate", "low"]
    basis: str = Field(min_length=1)


class QuantumCapabilityProfile(TrinetraModel):
    profile_type: Literal["quantum_capability"]
    version: str = Field(pattern=r"^quantum-capability-\d{4}\.\d+$")
    reference_year: int = Field(ge=2026)
    sources: list[ProfileSource] = Field(min_length=1)
    scenarios: dict[Literal["conservative", "baseline", "aggressive"], float]
    capability_curve: list[CapabilityPoint] = Field(min_length=1)
    attack_models: list[AttackModel] = Field(min_length=1)

    @field_validator("scenarios")
    @classmethod
    def _scenarios_have_fixed_scales(cls, values: dict[str, float]) -> dict[str, float]:
        expected = {"conservative": 0.5, "baseline": 1.0, "aggressive": 2.0}
        if values != expected:
            raise ValueError(
                "scenarios must be conservative=0.5, baseline=1.0, aggressive=2.0"
            )
        return values

    @model_validator(mode="after")
    def _curve_and_models_are_auditable(self) -> QuantumCapabilityProfile:
        years = [point.year for point in self.capability_curve]
        if years != sorted(years) or len(years) != len(set(years)):
            raise ValueError("capability_curve years must be unique and ascending")
        source_ids = {source.source_id for source in self.sources}
        missing_sources = sorted(
            model.source_id
            for model in self.attack_models
            if model.source_id not in source_ids
        )
        if missing_sources:
            raise ValueError(
                f"attack models reference unknown sources: {missing_sources}"
            )
        return self


class RiskWeightsProfile(TrinetraModel):
    profile_type: Literal["risk_weights"]
    version: str = Field(pattern=r"^risk-weights-\d{4}\.\d+$")
    sources: list[ProfileSource] = Field(min_length=1)
    weights: dict[str, int]
    bands: dict[str, int]
    scoring: dict[str, object]

    @model_validator(mode="after")
    def _weights_total_the_band_max(self) -> RiskWeightsProfile:
        if self.weights != FACTOR_WEIGHTS:
            raise ValueError(
                "risk weights must use the canonical seven factors and maxima"
            )
        if sum(self.weights.values()) != 100:
            raise ValueError("risk weights must total the 100-point band maximum")
        if self.bands != {"p0": 75, "p1": 50}:
            raise ValueError("risk bands must be p0=75 and p1=50")
        return self


class CurrentSecurityProfile(TrinetraModel):
    profile_type: Literal["current_security"]
    version: str = Field(pattern=r"^current-security-\d{4}\.\d+$")
    sources: list[ProfileSource] = Field(min_length=1)
    classically_broken_algorithms: list[str] = Field(min_length=1)
    quantum_resistant_algorithms: list[str] = Field(min_length=1)


type Profile = (
    RetentionProfile
    | QuantumCapabilityProfile
    | RiskWeightsProfile
    | CurrentSecurityProfile
)


class RiskProfiles(TrinetraModel):
    """The four Phase-5 policy artefacts consumed by a classification run."""

    retention: RetentionProfile
    quantum: QuantumCapabilityProfile
    weights: RiskWeightsProfile
    current_security: CurrentSecurityProfile


_PROFILE_DIR = Path(__file__).parent
_PROFILE_FILES = {
    "retention-policy-2026.1": "retention-policy-2026.1.json",
    "quantum-capability-2026.2": "quantum-capability-2026.2.json",
    "risk-weights-2026.1": "risk-weights-2026.1.json",
    "current-security-2026.1": "current-security-2026.1.json",
}

# These names have been persisted in early settings rows.  They deliberately
# resolve to their maintained successors so historic configuration can still be
# opened and resubmitted; new assessments store the canonical profile version.
_PROFILE_ALIASES = {
    "builtin-0.1.0": "current-security-2026.1",
    "quantum-capability-2026.1": "quantum-capability-2026.2",
    "nist-pqc-fit-2026.1": "current-security-2026.1",
}


def canonical_profile_version(version: str) -> str:
    """Return the maintained profile version for a persisted version string."""
    return _PROFILE_ALIASES.get(version, version)


@cache
def load_profile(version: str) -> Profile:
    """Load and validate one profile, caching only a successfully parsed value."""
    canonical_version = canonical_profile_version(version)
    filename = _PROFILE_FILES.get(canonical_version)
    if filename is None:
        raise ProfileError(f"unknown profile version {version!r}")

    path = _PROFILE_DIR / filename
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProfileError(
            f"could not read profile {canonical_version!r}: {error}"
        ) from error

    model_by_type = {
        "retention_policy": RetentionProfile,
        "quantum_capability": QuantumCapabilityProfile,
        "risk_weights": RiskWeightsProfile,
        "current_security": CurrentSecurityProfile,
    }
    profile_type = payload.get("profile_type") if isinstance(payload, dict) else None
    model = model_by_type.get(profile_type)
    if model is None:
        raise ProfileError(
            f"profile {canonical_version!r} has unsupported profile_type {profile_type!r}"
        )
    try:
        profile = model.model_validate(payload)
    except ValidationError as error:
        raise ProfileError(f"invalid profile {canonical_version!r}: {error}") from error
    if profile.version != canonical_version:
        raise ProfileError(
            f"profile filename requested {canonical_version!r} but declares "
            f"{profile.version!r}"
        )
    return profile


def load_risk_profiles(
    *,
    retention_version: str = "retention-policy-2026.1",
    quantum_version: str = "quantum-capability-2026.2",
    weights_version: str = "risk-weights-2026.1",
    current_security_version: str = "current-security-2026.1",
) -> RiskProfiles:
    """Load the complete, validated policy set for one deterministic run."""
    retention = load_profile(retention_version)
    quantum = load_profile(quantum_version)
    weights = load_profile(weights_version)
    security = load_profile(current_security_version)
    if not isinstance(retention, RetentionProfile):  # pragma: no cover - defensive
        raise ProfileError("retention version did not resolve to a retention profile")
    if not isinstance(quantum, QuantumCapabilityProfile):  # pragma: no cover
        raise ProfileError("quantum version did not resolve to a quantum profile")
    if not isinstance(weights, RiskWeightsProfile):  # pragma: no cover
        raise ProfileError("weights version did not resolve to a risk-weights profile")
    if not isinstance(security, CurrentSecurityProfile):  # pragma: no cover
        raise ProfileError("security version did not resolve to a security profile")
    return RiskProfiles(
        retention=retention,
        quantum=quantum,
        weights=weights,
        current_security=security,
    )


__all__ = [
    "CurrentSecurityProfile",
    "ProfileError",
    "QuantumCapabilityProfile",
    "RetentionProfile",
    "RiskProfiles",
    "RiskWeightsProfile",
    "canonical_profile_version",
    "load_profile",
    "load_risk_profiles",
]
