"""Shared value objects: evidence, provenance and the deterministic artefact id.

These types are used by every artefact schema. They encode two of the platform's
principles directly in the type system:

* **P3** -- :class:`Evidence` is required on every finding. A finding with no
  evidence cannot be constructed, so an unsourced artefact is a type error rather
  than a silent low-quality row.
* **P4** -- :class:`Provenance` records which tier supplied each context field, so
  no number can reach the UI without its origin.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import Confidence, DetectionMethod, ProvenanceTier

#: Bumped whenever the artefact identity inputs change. A change here re-keys
#: every artefact, so it is deliberately explicit rather than derived.
ARTEFACT_ID_VERSION = "1"


class TrinetraModel(BaseModel):
    """Base for every schema in the platform.

    ``extra="forbid"`` is deliberate: an unexpected field from a scanner is a
    contract drift and must fail loudly at the boundary (defence in depth
    alongside the JSON Schema validation), not be silently dropped.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=False,
        use_enum_values=False,
        validate_assignment=True,
        str_strip_whitespace=True,
    )


class SourceLocation(TrinetraModel):
    """Where in a target a finding was observed."""

    path: str = Field(
        description="Path relative to the scan target root. Never an absolute "
        "host path -- that would leak the scanner's filesystem layout."
    )
    line: int | None = Field(
        default=None, ge=1, description="1-indexed line number, when known."
    )
    column: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    symbol: str | None = Field(
        default=None,
        description="Enclosing function/class, or the binary symbol name.",
    )

    @field_validator("path")
    @classmethod
    def _reject_absolute_paths(cls, value: str) -> str:
        if value.startswith("/") or (len(value) > 1 and value[1] == ":"):
            raise ValueError(
                "location.path must be relative to the scan target root; "
                f"got absolute path {value!r}"
            )
        return value

    def render(self) -> str:
        """Human-readable location, matching the ingest mapping's ``location``."""
        if self.line is None:
            return self.path
        return f"{self.path}, line {self.line}"


class Evidence(TrinetraModel):
    """Why Trinetra believes a finding is real.

    Every artefact carries one. An artefact without evidence is not a
    lower-quality artefact -- it is a bug, so the field is mandatory.
    """

    location: SourceLocation
    detection_method: DetectionMethod
    confidence: Confidence
    snippet: str | None = Field(
        default=None,
        max_length=2000,
        description="The source line(s) that triggered detection. Redacted "
        "before storage when the match is key material.",
    )
    rule_id: str | None = Field(
        default=None, description="Identifier of the rule that fired."
    )
    additional_context: str | None = Field(
        default=None,
        description="Scanner-supplied note, e.g. the data-flow sink reached.",
    )
    redacted: bool = Field(
        default=False,
        description="True when the snippet was withheld or masked because it "
        "contained key material. The platform must never log a real key.",
    )


class Provenance(TrinetraModel):
    """Which tier supplied a single context field, and why (P4)."""

    tier: ProvenanceTier
    source_detail: str | None = Field(
        default=None,
        description="Identifier within the tier, e.g. the org preset name or "
        "the taint rule that produced the evidence.",
    )

    @property
    def is_known(self) -> bool:
        return self.tier is not ProvenanceTier.UNKNOWN


def _canonical_json(payload: Any) -> str:
    """Serialise deterministically: sorted keys, no insignificant whitespace.

    Byte-identical output for identical input is a tested property of the
    contract, so this must never depend on dict ordering.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_artefact_id(
    *,
    scan_target: str,
    asset_type: str,
    name: str,
    location_path: str,
    location_line: int | None,
    discriminator: str | None = None,
) -> str:
    """Return the deterministic identity of an artefact.

    The same artefact found again in a later scan of the same target yields the
    same id, which is what makes "has this been fixed?" answerable across scans.

    Line number is included because two distinct uses of ``AES`` in one file are
    two findings that may carry different context and be remediated separately.
    ``discriminator`` separates artefacts that would otherwise collide on one
    line, such as two algorithms named in a single cipher-suite string.
    """
    digest_input = _canonical_json(
        {
            "v": ARTEFACT_ID_VERSION,
            "target": scan_target,
            "type": asset_type,
            "name": name,
            "path": location_path,
            "line": location_line,
            "discriminator": discriminator,
        }
    )
    return hashlib.sha256(digest_input.encode("utf-8")).hexdigest()


__all__ = [
    "ARTEFACT_ID_VERSION",
    "Evidence",
    "Provenance",
    "SourceLocation",
    "TrinetraModel",
    "compute_artefact_id",
]
