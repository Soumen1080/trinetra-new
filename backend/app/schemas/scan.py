"""The scan envelope and its coverage statistics (plan task 1.11).

A scan result is not just a list of artefacts. It carries **what the scanner
could not see**, because anything omitted silently reads to the user as
"clean" -- and a repository reported clean because three files failed to parse is
a more dangerous output than an honest error.
"""

from __future__ import annotations

from datetime import datetime
from typing import Self

from pydantic import Field, model_validator

from app.models.enums import ScannerKind, ScanStatus, ScanTargetKind
from app.schemas.artefact import CryptoArtefact
from app.schemas.common import TrinetraModel


class ScanTarget(TrinetraModel):
    """What was scanned."""

    kind: ScanTargetKind
    identifier: str = Field(
        min_length=1,
        description="Repository URL, image reference, host:port or path. Also "
        "the target component of every artefact's deterministic id, so it must "
        "be stable across scans of the same thing.",
    )
    reference: str | None = Field(
        default=None, description="Branch, tag, digest or commit."
    )
    display_name: str | None = None


class ToolVersion(TrinetraModel):
    """A tool that contributed to the scan.

    Recorded so a finding can be re-derived later: "why did last month's scan
    miss this?" is usually answered by a rule-pack version.
    """

    name: str
    version: str
    ruleset_version: str | None = None


class CoverageGap(TrinetraModel):
    """Something the scanner could not inspect.

    Surfaced in the UI, not only in the report. A stripped binary that could not
    be analysed is a hole in the inventory, and the user must see the hole.
    """

    path: str | None = None
    reason: str = Field(
        min_length=1,
        description="Plain language, e.g. 'binary is stripped; symbol table "
        "unavailable' or 'file exceeds 10 MB scan limit'.",
    )
    kind: str = Field(
        description="unparseable | skipped | too_large | timeout | "
        "unsupported_language | permission_denied"
    )
    count: int = Field(default=1, ge=1)


class CoverageStats(TrinetraModel):
    """How much of the target was actually inspected."""

    files_discovered: int = Field(default=0, ge=0)
    files_scanned: int = Field(default=0, ge=0)
    files_skipped: int = Field(default=0, ge=0)
    bytes_scanned: int = Field(default=0, ge=0)
    languages_detected: list[str] = Field(default_factory=list)
    gaps: list[CoverageGap] = Field(default_factory=list)

    @model_validator(mode="after")
    def _scanned_within_discovered(self) -> Self:
        if self.files_scanned > self.files_discovered:
            raise ValueError("files_scanned exceeds files_discovered")
        return self

    @property
    def coverage_ratio(self) -> float | None:
        """Fraction of discovered files actually scanned.

        ``None`` when nothing was discovered: 0/0 is not 100% coverage, and
        rendering it as such would claim a complete inventory of nothing.
        """
        if self.files_discovered == 0:
            return None
        return self.files_scanned / self.files_discovered

    @property
    def is_complete(self) -> bool:
        """Whether every discovered file was actually inspected.

        Checks the scanned/discovered counts as well as the recorded gaps: a
        scanner that silently dropped files without logging a gap would
        otherwise report complete coverage over a partial inventory.
        """
        if self.gaps or self.files_skipped:
            return False
        return self.files_scanned == self.files_discovered


class ScanError(TrinetraModel):
    """A failure during a scan.

    ``is_retryable`` exists so the worker does not spend three attempts on a
    malformed URL, and does retry a transient registry timeout.
    """

    code: str
    message: str
    scanner: ScannerKind | None = None
    is_retryable: bool = False
    occurred_at: datetime | None = None


class ScanResult(TrinetraModel):
    """The complete output of one scan (plan task 1.11).

    This envelope is what a scanner returns and what ingest consumes. It is
    deliberately self-describing: target, tools, artefacts, coverage and errors
    travel together, so a stored result can be audited without reference to the
    system that produced it.
    """

    scan_id: str
    target: ScanTarget
    status: ScanStatus

    started_at: datetime
    finished_at: datetime | None = None

    scanners_run: list[ScannerKind] = Field(default_factory=list)
    tool_versions: list[ToolVersion] = Field(default_factory=list)
    schema_version: str = Field(
        default="1.0", description="Version of the artefact contract in use."
    )

    artefacts: list[CryptoArtefact] = Field(default_factory=list)
    coverage: CoverageStats = Field(default_factory=CoverageStats)
    errors: list[ScanError] = Field(default_factory=list)

    requested_by: str | None = None
    idempotency_key: str | None = None

    @model_validator(mode="after")
    def _terminal_scans_have_finished(self) -> Self:
        if self.status.is_terminal and self.finished_at is None:
            raise ValueError(
                f"scan in terminal status {self.status.value!r} must record "
                "finished_at"
            )
        if self.finished_at is not None and self.finished_at < self.started_at:
            raise ValueError("finished_at precedes started_at")
        return self

    @model_validator(mode="after")
    def _failed_scans_explain_themselves(self) -> Self:
        """A failed scan must say why.

        Otherwise the user sees a red badge with no cause and no action, which
        is the hang that has no user-visible end.
        """
        if self.status is ScanStatus.FAILED and not self.errors:
            raise ValueError("a failed scan must record at least one error")
        return self

    @property
    def artefact_count(self) -> int:
        return len(self.artefacts)

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    def artefacts_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for artefact in self.artefacts:
            key = artefact.asset_type.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def deduplicated(self) -> list[CryptoArtefact]:
        """Merge artefacts sharing an identity, preserving discovery order.

        Two scanners finding the same asset is corroboration, not duplication,
        so their evidence is unioned onto a single artefact.
        """
        merged: dict[str, CryptoArtefact] = {}
        for artefact in self.artefacts:
            existing = merged.get(artefact.artefact_id)
            merged[artefact.artefact_id] = (
                existing.merged_with(artefact) if existing else artefact
            )
        return list(merged.values())


__all__ = [
    "CoverageGap",
    "CoverageStats",
    "ScanError",
    "ScanResult",
    "ScanTarget",
    "ToolVersion",
]
