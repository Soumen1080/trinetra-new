"""Business context and the provenance chain (plan tasks 1.9 - 1.10).

No scanner can know how long the data an artefact protects must stay secret, or
whether the service is a payment gateway or a toy script. ``RSA.generate(2048)``
looks identical in both. Context is therefore resolved through a strict
precedence chain, and **every field records which tier supplied it**.

Two rules are enforced here rather than left to convention:

* **A file path is never business context.** ``/payments/`` in a path is a naming
  coincidence, not evidence that the code handles payments.
* **The ``scanner_evidence`` tier is narrowed to ``data_category`` alone**, so a
  future scanner cannot become a back-channel for facts no scanner can know.
"""

from __future__ import annotations

from datetime import datetime
from typing import Self

from pydantic import Field, model_validator

from app.models.enums import (
    BusinessCriticality,
    DataClassification,
    DependencyRelation,
    EvidenceSource,
    ExposureLevel,
    ProvenanceTier,
    RetentionBasis,
)
from app.schemas.common import Provenance, TrinetraModel

#: The only context field a scanner may supply. Widening this set would let a
#: scanner assert business facts it cannot observe.
SCANNER_SUPPLIABLE_FIELDS: frozenset[str] = frozenset({"data_category"})


class Application(TrinetraModel):
    """A system that owns artefacts (plan task 1.9).

    Supplies the business inputs to the risk engine: criticality, data
    classification, exposure and retention. Every one defaults to ``UNKNOWN``
    or ``None`` rather than to a middle value (P3).
    """

    application_id: str
    name: str = Field(min_length=1)
    description: str | None = None

    owner: str | None = Field(
        default=None, description="Team or individual accountable for migration."
    )
    owner_email: str | None = None

    business_criticality: BusinessCriticality = BusinessCriticality.UNKNOWN
    data_classification: DataClassification = DataClassification.UNKNOWN
    exposure: ExposureLevel = ExposureLevel.UNKNOWN

    data_retention_years: int | None = Field(
        default=None,
        ge=0,
        description="How long the data must remain confidential -- Mosca's X. "
        "None means no evidence supported a value; the engine then reports no X "
        "rather than assuming one.",
    )
    migration_time_years: float | None = Field(
        default=None,
        ge=0,
        description="Mosca's Y. Supplied by a human -- **never inferred**. "
        "Trinetra cannot see team capacity, budget cycles or vendor roadmaps.",
    )

    tags: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None


class RetentionEvidence(TrinetraModel):
    """One piece of evidence for the confidentiality lifetime X."""

    source: EvidenceSource
    data_category: str = Field(
        description="e.g. aadhaar_pii, health_record, session_token."
    )
    lifetime_years: int = Field(ge=0)
    basis: RetentionBasis
    citation: str | None = Field(
        default=None, description="Statute, policy id or profile entry."
    )
    caveat: str | None = Field(
        default=None,
        description="Printed with the figure wherever it appears. Retention "
        "minimums in particular are not confidentiality lifetimes.",
    )

    @model_validator(mode="after")
    def _regulatory_minimums_carry_their_caveat(self) -> Self:
        """A regulatory minimum without its caveat is a misleading number.

        Statutes mandate how long data must be *kept*, which says nothing about
        how long it must stay *secret*. Presenting one as the other silently
        overstates or understates X, so the caveat is mandatory.
        """
        if self.basis is RetentionBasis.REGULATORY_MINIMUM and not self.caveat:
            raise ValueError(
                "regulatory_minimum evidence must carry a caveat: a retention "
                "minimum is not a confidentiality lifetime"
            )
        return self


class ArtefactContext(TrinetraModel):
    """Resolved business context for one artefact, with per-field provenance.

    Created by the context resolver, editable by a user. The ``provenance`` map
    is what lets the UI show *where each number came from* (P4, and UI
    obligation O2).
    """

    artefact_id: str
    application_id: str | None = None

    business_criticality: BusinessCriticality = BusinessCriticality.UNKNOWN
    data_classification: DataClassification = DataClassification.UNKNOWN
    exposure: ExposureLevel = ExposureLevel.UNKNOWN
    data_category: str | None = None

    data_lifetime_years: int | None = Field(
        default=None, ge=0, description="Resolved X. None when unevidenced."
    )
    migration_time_years: float | None = Field(
        default=None, ge=0, description="Resolved Y. Human-supplied only."
    )

    retention_evidence: list[RetentionEvidence] = Field(default_factory=list)
    provenance: dict[str, Provenance] = Field(
        default_factory=dict,
        description="field name -> which tier supplied it. Fields absent from "
        "this map were never resolved and must render as 'unknown', not as a "
        "value with no origin.",
    )

    updated_at: datetime | None = None
    updated_by: str | None = None

    @model_validator(mode="after")
    def _scanner_tier_is_narrowed(self) -> Self:
        """Enforce that scanners supply only ``data_category``.

        Without this check, a future scanner could set ``business_criticality``
        from a directory name and the value would carry scanner provenance,
        which reads as evidence rather than as the guess it is.
        """
        for field_name, prov in self.provenance.items():
            if (
                prov.tier is ProvenanceTier.SCANNER_EVIDENCE
                and field_name not in SCANNER_SUPPLIABLE_FIELDS
            ):
                raise ValueError(
                    f"field {field_name!r} cannot carry scanner_evidence "
                    f"provenance; scanners may supply only "
                    f"{sorted(SCANNER_SUPPLIABLE_FIELDS)}"
                )
        return self

    def provenance_of(self, field_name: str) -> Provenance:
        """Provenance for ``field_name``, defaulting to the ``unknown`` tier."""
        return self.provenance.get(
            field_name, Provenance(tier=ProvenanceTier.UNKNOWN)
        )

    @property
    def missing_fields(self) -> list[str]:
        """Context fields with no resolved value.

        Drives the ``NEEDS_CONTEXT`` display, which must name what is missing
        rather than leaving the user at a dead end.
        """
        missing: list[str] = []
        if self.business_criticality is BusinessCriticality.UNKNOWN:
            missing.append("business_criticality")
        if self.data_classification is DataClassification.UNKNOWN:
            missing.append("data_classification")
        if self.exposure is ExposureLevel.UNKNOWN:
            missing.append("exposure")
        if self.data_lifetime_years is None:
            missing.append("data_lifetime_years")
        if self.migration_time_years is None:
            missing.append("migration_time_years")
        return missing


class DependencyEdge(TrinetraModel):
    """One edge in the crypto dependency graph (plan task 1.10).

    Application -> library -> algorithm. Answers "if OpenSSL is the problem,
    what breaks?", which is the blast-radius question behind migration planning.
    """

    source_id: str = Field(description="artefact_id or application_id.")
    target_id: str
    relation: DependencyRelation
    source_kind: str = Field(description="'application' or 'artefact'.")
    target_kind: str = Field(description="'application' or 'artefact'.")
    is_direct: bool = True
    depth: int = Field(
        default=0, ge=0, description="0 for direct, incrementing transitively."
    )

    @model_validator(mode="after")
    def _no_self_edges(self) -> Self:
        if self.source_id == self.target_id:
            raise ValueError("a dependency edge cannot point at itself")
        return self


__all__ = [
    "SCANNER_SUPPLIABLE_FIELDS",
    "Application",
    "ArtefactContext",
    "DependencyEdge",
    "RetentionEvidence",
]
