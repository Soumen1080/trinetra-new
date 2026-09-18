"""PQC recommendation records: cited facts separated from unmeasured effects."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from app.schemas.artefact import CryptoArtefact
from app.schemas.common import TrinetraModel
from app.schemas.risk import RiskAssessment


class PublishedPqcFacts(TrinetraModel):
    """Object sizes published by a cited standard, rather than a fit estimate."""

    source_id: str = Field(min_length=1)
    source_url: str = Field(min_length=1)
    public_key_bytes: int | None = Field(default=None, gt=0)
    private_key_bytes: int | None = Field(default=None, gt=0)
    ciphertext_bytes: int | None = Field(default=None, gt=0)
    signature_bytes: int | None = Field(default=None, gt=0)
    symmetric_key_bytes: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def _has_a_fact(self) -> Self:
        if all(
            value is None
            for value in (
                self.public_key_bytes,
                self.private_key_bytes,
                self.ciphertext_bytes,
                self.signature_bytes,
                self.symmetric_key_bytes,
            )
        ):
            raise ValueError(
                "published PQC facts must include at least one object size"
            )
        return self


class DeploymentDimension(TrinetraModel):
    """An impact dimension whose absence is visible instead of fabricated."""

    name: Literal["latency", "protocol_compatibility", "mtu_impact", "cost"]
    status: Literal["unmeasured", "measured"]
    value: str | float | int | None = None
    unit: str | None = None
    evidence: str | None = None

    @model_validator(mode="after")
    def _measurement_state_is_honest(self) -> Self:
        if self.status == "unmeasured" and self.value is not None:
            raise ValueError(
                "an unmeasured deployment dimension must not carry a value"
            )
        if self.status == "measured" and (self.value is None or not self.evidence):
            raise ValueError(
                "a measured deployment dimension needs a value and evidence"
            )
        return self


class RecommendationRequirements(TrinetraModel):
    """Deployment choices that the scanner cannot infer and must be explicit."""

    required_security_category: Literal[1, 3, 5] | None = None
    hybrid_required: bool = False
    stateless_required: bool = False


class RecommendationContext(TrinetraModel):
    """All observed and user-supplied inputs to a pure recommendation run."""

    recommendation_id: str = Field(min_length=1, max_length=64)
    artefact: CryptoArtefact
    assessment: RiskAssessment
    requirements: RecommendationRequirements = Field(
        default_factory=RecommendationRequirements
    )

    @model_validator(mode="after")
    def _artefact_and_assessment_agree(self) -> Self:
        if self.artefact.artefact_id != self.assessment.artefact_id:
            raise ValueError("recommendation context joins different artefacts")
        return self


class CryptoAgilityObservation(TrinetraModel):
    """An explicit migration observation; scanners must not guess this fact."""

    status: Literal["unmeasured", "hardcoded", "config_driven"] = "unmeasured"
    evidence: str | None = None

    @model_validator(mode="after")
    def _observed_states_have_evidence(self) -> Self:
        if self.status != "unmeasured" and not self.evidence:
            raise ValueError("a crypto-agility observation needs evidence")
        return self


class MigrationPlanItem(TrinetraModel):
    """A non-scored migration action, ordered by dependencies and deadline."""

    recommendation_id: str
    assessment_id: str
    artefact_id: str
    migration_wave: int = Field(ge=1)
    mosca_deadline_year: int | None = None
    dependency_ids: list[str] = Field(default_factory=list)
    hardware_action: Literal["none", "verify_firmware", "hardware_purchase"] = "none"
    crypto_agility: CryptoAgilityObservation = Field(
        default_factory=CryptoAgilityObservation
    )
    notes: list[str] = Field(default_factory=list)


class MigrationPlan(TrinetraModel):
    """Ordered result of migration planning, separate from risk scoring."""

    items: list[MigrationPlanItem] = Field(default_factory=list)


class PqcRecommendation(TrinetraModel):
    """One cited migration recommendation for an actionable assessment."""

    recommendation_id: str
    assessment_id: str
    recommended_algorithm: str | None = None
    recommended_parameter_set: str | None = None
    security_category: Literal[1, 3, 5] | None = None
    classical_partner: str | None = None
    is_hybrid: bool = False
    requires_manual_review: bool = False

    rationale: str = Field(min_length=1)
    published_facts: PublishedPqcFacts | None = None
    deployment_dimensions: list[DeploymentDimension] = Field(default_factory=list)
    fit_score: None = Field(
        default=None,
        description="Always null: FIPS object sizes cannot yield a universal fit score.",
    )
    profile_version: str = Field(min_length=1)

    @model_validator(mode="after")
    def _manual_and_automatic_paths_are_complete(self) -> Self:
        if self.requires_manual_review:
            if self.recommended_algorithm is not None or self.published_facts is not None:
                raise ValueError(
                    "manual review must not pretend to have an automatic choice"
                )
            return self
        if self.recommended_algorithm is None or self.published_facts is None:
            raise ValueError(
                "automatic recommendations require algorithm and cited facts"
            )
        if self.is_hybrid and not self.classical_partner:
            raise ValueError("hybrid recommendations require a classical partner")
        if not self.deployment_dimensions:
            raise ValueError("recommendations must state deployment measurement status")
        return self


class MigrationCandidate(TrinetraModel):
    """One actionable recommendation considered by the pure wave planner."""

    artefact: CryptoArtefact
    assessment: RiskAssessment
    recommendation: PqcRecommendation
    crypto_agility: CryptoAgilityObservation = Field(
        default_factory=CryptoAgilityObservation
    )

    @model_validator(mode="after")
    def _candidate_is_consistent(self) -> Self:
        if self.artefact.artefact_id != self.assessment.artefact_id:
            raise ValueError("migration candidate joins different artefacts")
        if self.assessment.assessment_id != self.recommendation.assessment_id:
            raise ValueError("migration candidate joins different assessments")
        return self


__all__ = [
    "CryptoAgilityObservation",
    "DeploymentDimension",
    "MigrationCandidate",
    "MigrationPlan",
    "MigrationPlanItem",
    "PqcRecommendation",
    "PublishedPqcFacts",
    "RecommendationContext",
    "RecommendationRequirements",
]
