"""Risk assessment records: both tracks, stored in full.

Phase 5 implements the engines; this module defines the **shape of their
output**, which the data model must freeze now because the tables and the API
depend on it.

Three guarantees are encoded structurally rather than left to the engine:

* A factor with no evidence contributes zero **and says so**
  (:class:`ScoreContribution.has_evidence`).
* There is no score unless both tracks produced a result
  (:meth:`RiskAssessment._score_requires_both_tracks`).
* Every verdict stores its inputs, so it can be re-derived and audited (P5).
"""

from __future__ import annotations

from datetime import datetime
from typing import Self

from pydantic import Field, model_validator

from app.models.enums import (
    AssessmentStatus,
    Confidence,
    MoscaZBasis,
    Priority,
    QuantumProjectionStatus,
    ResourceScenario,
)
from app.schemas.common import TrinetraModel

#: Maximum points each factor may contribute. Sums to 100.
FACTOR_WEIGHTS: dict[str, int] = {
    "algorithm_quantum_vulnerability": 25,
    "mosca_timing_risk": 20,
    "resource_feasibility": 15,
    "data_sensitivity": 12,
    "business_criticality": 10,
    "exposure": 10,
    "migration_complexity": 8,
}

#: Score bands. >= 75 -> P0, 50-74 -> P1, < 50 -> P2.
P0_THRESHOLD = 75
P1_THRESHOLD = 50


class ScoreContribution(TrinetraModel):
    """One factor's contribution to the final score.

    ``has_evidence=False`` with ``points=0`` is the honest representation of an
    unmeasured factor. The alternative -- a midpoint -- is indistinguishable
    from a real measurement once it reaches a chart.
    """

    factor: str
    points: float = Field(ge=0)
    max_points: int = Field(gt=0)
    has_evidence: bool
    reason: str = Field(
        min_length=1,
        description="Plain language, shown in the UI beside the number.",
    )

    @model_validator(mode="after")
    def _no_points_without_evidence(self) -> Self:
        if not self.has_evidence and self.points != 0:
            raise ValueError(
                f"factor {self.factor!r} has no evidence but contributed "
                f"{self.points} points; an unmeasured factor must contribute zero"
            )
        if self.points > self.max_points:
            raise ValueError(
                f"factor {self.factor!r} contributed {self.points} points, "
                f"exceeding its maximum of {self.max_points}"
            )
        return self


class MoscaTrack(TrinetraModel):
    """Track A -- will migration finish before the data stops being safe?

    ``X + Y > Z`` means the deadline has already passed.
    """

    x_years: int | None = Field(
        default=None, ge=0, description="Confidentiality lifetime. None when unevidenced."
    )
    y_years: float | None = Field(
        default=None, ge=0, description="Migration time. Human-supplied only."
    )
    z_years: float | None = Field(default=None, ge=0, description="Threat horizon.")
    z_basis: MoscaZBasis = MoscaZBasis.UNAVAILABLE

    is_urgent: bool | None = Field(
        default=None,
        description="True when X + Y > Z. None when any input is missing -- "
        "which is not the same as 'not urgent'.",
    )
    shortfall_years: float | None = Field(
        default=None,
        description="(X + Y) - Z. Positive means the deadline has passed; "
        "negative is remaining slack.",
    )
    confidence: Confidence | None = None
    evidence: list[str] = Field(
        default_factory=list, description="Human-readable citations for X."
    )

    @property
    def is_resolved(self) -> bool:
        return None not in (self.x_years, self.y_years, self.z_years)

    @model_validator(mode="after")
    def _verdict_requires_all_three_inputs(self) -> Self:
        """X + Y > Z cannot be evaluated with a missing term.

        Treating an absent X as zero would silently turn every unevidenced
        artefact into "not urgent", which is the most consequential possible
        false negative in the platform.
        """
        if self.is_urgent is not None and not self.is_resolved:
            raise ValueError(
                "mosca verdict requires x, y and z; missing inputs must yield "
                "is_urgent=None rather than a default"
            )
        return self


class ResourceTrack(TrinetraModel):
    """Track B -- when could this algorithm become attack-feasible?

    Q (the attack requirement) is a property of the algorithm. A scenario scales
    the capability curve P(t) and **never** Q, so roadmap optimism cannot alter
    how hard an algorithm is to break.
    """

    m_years: float | None = Field(
        default=None, ge=0, description="Years until attack feasibility."
    )
    scenario: ResourceScenario = ResourceScenario.BASELINE
    status: QuantumProjectionStatus = QuantumProjectionStatus.MODEL_UNAVAILABLE

    projected_break_year: int | None = None
    migration_deadline_year: int | None = None

    logical_qubits_required: int | None = Field(default=None, gt=0)
    gate_count_required: float | None = Field(default=None, gt=0)

    assumptions: dict[str, str] = Field(
        default_factory=dict,
        description="Error-correction scheme, logical-qubit definition, physical "
        "error rate. A Q without its assumptions is a number nobody can check.",
    )
    caveats: list[str] = Field(default_factory=list)
    confidence: Confidence | None = None

    @property
    def is_resolved(self) -> bool:
        return (
            self.status is QuantumProjectionStatus.CALCULATED
            and self.m_years is not None
        )

    @model_validator(mode="after")
    def _calculated_results_carry_assumptions(self) -> Self:
        """A computed Q must travel with the assumptions behind it (P4)."""
        if (
            self.status is QuantumProjectionStatus.CALCULATED
            and self.logical_qubits_required is not None
            and not self.assumptions
        ):
            raise ValueError(
                "a calculated quantum resource estimate must record its "
                "assumptions; an unqualified qubit count cannot be checked"
            )
        return self


class RiskAssessment(TrinetraModel):
    """One verdict for one artefact. **Append-only** -- never updated (P5).

    Re-scoring inserts a new row, which is what makes "why was this P0 last
    week?" an answerable question.
    """

    assessment_id: str
    artefact_id: str
    scan_id: str | None = None

    status: AssessmentStatus
    final_score: float | None = Field(
        default=None,
        ge=0,
        le=100,
        description="None unless both tracks produced a result. Half the "
        "evidence still makes a number; it is just not a comparable one.",
    )
    final_confidence: Confidence | None = None
    priority: Priority = Priority.NONE

    mosca: MoscaTrack = Field(default_factory=MoscaTrack)
    resource: ResourceTrack = Field(default_factory=ResourceTrack)

    contributions: list[ScoreContribution] = Field(default_factory=list)
    missing_fields: list[str] = Field(
        default_factory=list,
        description="Named so NEEDS_CONTEXT is an action, not a dead end.",
    )
    rationale: str | None = Field(
        default=None, description="Plain-language explanation shown in the UI."
    )

    policy_version: str
    weights_version: str
    quantum_forecast_profile_version: str | None = None

    assessed_at: datetime
    input_provenance: dict[str, str] = Field(
        default_factory=dict,
        description="Which tier supplied each input, copied from the context at "
        "assessment time so the verdict stays reproducible even if the context "
        "is later edited.",
    )

    @model_validator(mode="after")
    def _score_requires_both_tracks(self) -> Self:
        """No score unless both tracks resolved.

        Ranking one artefact scored on both tracks against another scored on one
        compares numbers that do not mean the same thing.
        """
        if self.final_score is not None and not (
            self.mosca.is_resolved and self.resource.is_resolved
        ):
            raise ValueError(
                "final_score requires both tracks to have produced a result; "
                "set status=needs_context and leave the score None instead"
            )
        return self

    @model_validator(mode="after")
    def _only_scored_assessments_carry_a_score(self) -> Self:
        if self.status is AssessmentStatus.SCORED and self.final_score is None:
            raise ValueError("status 'scored' requires a final_score")
        if self.status is not AssessmentStatus.SCORED and self.final_score is not None:
            raise ValueError(
                f"status {self.status.value!r} must not carry a score; "
                "scoring a policy-decided artefact implies a measurement that "
                "was never made"
            )
        return self

    @model_validator(mode="after")
    def _needs_context_names_what_is_missing(self) -> Self:
        if self.status is AssessmentStatus.NEEDS_CONTEXT and not self.missing_fields:
            raise ValueError(
                "needs_context assessments must name the missing fields so the "
                "user has an action rather than a dead end"
            )
        return self

    @model_validator(mode="after")
    def _priority_matches_score(self) -> Self:
        if self.final_score is None:
            if self.priority is not Priority.NONE:
                raise ValueError(
                    "an unscored assessment cannot carry a priority band; "
                    "unassessed artefacts must not be sorted as if they were low risk"
                )
            return self

        expected = band_for_score(self.final_score)
        if self.priority is not expected:
            raise ValueError(
                f"priority {self.priority.value!r} does not match score "
                f"{self.final_score} (expected {expected.value!r})"
            )
        return self

    @property
    def has_score(self) -> bool:
        return self.final_score is not None

    @property
    def unmeasured_factors(self) -> list[str]:
        return [c.factor for c in self.contributions if not c.has_evidence]


def band_for_score(score: float) -> Priority:
    """Map a score to its priority band."""
    if score >= P0_THRESHOLD:
        return Priority.P0
    if score >= P1_THRESHOLD:
        return Priority.P1
    return Priority.P2


__all__ = [
    "FACTOR_WEIGHTS",
    "P0_THRESHOLD",
    "P1_THRESHOLD",
    "MoscaTrack",
    "ResourceTrack",
    "RiskAssessment",
    "ScoreContribution",
    "band_for_score",
]
