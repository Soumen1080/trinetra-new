"""Request and response contracts generated into the Phase-9 client."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.models.enums import (
    BusinessCriticality,
    DataClassification,
    ExposureLevel,
    ResourceScenario,
    ScannerKind,
    ScanStatus,
    ScanTargetKind,
    UserRole,
)
from app.schemas.common import TrinetraModel
from app.schemas.context import RetentionEvidence


class TokenRequest(TrinetraModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class TokenResponse(TrinetraModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    csrf_token: str
    user: UserResponse


class UserResponse(TrinetraModel):
    id: str
    username: str
    email: str | None = None
    role: UserRole
    is_active: bool


class UserProvisionRequest(TrinetraModel):
    username: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=1024)
    email: str | None = Field(default=None, max_length=320)
    role: UserRole = UserRole.VIEWER
    project_ids: list[str] = Field(default_factory=list)


class UserUpdateRequest(TrinetraModel):
    role: UserRole | None = None
    is_active: bool | None = None


class ProjectCreateRequest(TrinetraModel):
    name: str = Field(min_length=1, max_length=255)
    tenant_id: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=10_000)


class ProjectResponse(TrinetraModel):
    id: str
    tenant_id: str
    name: str
    description: str | None = None


class ScanCreateRequest(TrinetraModel):
    target_kind: ScanTargetKind
    target_identifier: str = Field(min_length=1, max_length=1024)
    target_reference: str | None = Field(default=None, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    application_id: str | None = None
    scanners: list[ScannerKind] = Field(default_factory=list)

    @field_validator("target_identifier")
    @classmethod
    def _reject_control_characters(cls, value: str) -> str:
        if any(ord(character) < 32 for character in value):
            raise ValueError("target_identifier contains control characters")
        return value.strip()


class ScanResponse(TrinetraModel):
    id: str
    project_id: str | None = None
    target_kind: ScanTargetKind
    target_identifier: str
    target_reference: str | None = None
    display_name: str | None = None
    status: ScanStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    artefact_count: int = 0
    errors: list[dict[str, Any]] = Field(default_factory=list)


class PageMeta(TrinetraModel):
    offset: int = Field(ge=0)
    limit: int = Field(ge=1)
    total: int = Field(ge=0)


class ScanListResponse(TrinetraModel):
    items: list[ScanResponse]
    page: PageMeta


class ScanProgressResponse(TrinetraModel):
    sequence: int
    percent: float = Field(ge=0, le=100)
    stage: str
    counts: dict[str, int] = Field(default_factory=dict)
    message: str | None = None
    created_at: datetime


class ArtefactListItem(TrinetraModel):
    id: str
    scan_id: str
    application_id: str | None = None
    name: str
    type: str
    algorithm: str | None = None
    key_size_bits: int | None = None
    location: str | None = None
    discovered_by: str
    quantum_vulnerability: str
    risk_score: float | None = None
    priority: str = "none"
    assessment_status: str | None = None
    recommendation: str | None = None


class ArtefactFacets(TrinetraModel):
    type: dict[str, int] = Field(default_factory=dict)
    priority: dict[str, int] = Field(default_factory=dict)
    application: dict[str, int] = Field(default_factory=dict)
    algorithm: dict[str, int] = Field(default_factory=dict)


class ArtefactListResponse(TrinetraModel):
    items: list[ArtefactListItem]
    page: PageMeta
    facets: ArtefactFacets
    scan_status: ScanStatus | None = None
    partial_results: bool = False


class ContextPatchRequest(TrinetraModel):
    application_id: str | None = None
    business_criticality: BusinessCriticality | None = None
    data_classification: DataClassification | None = None
    exposure: ExposureLevel | None = None
    data_category: str | None = Field(default=None, max_length=128)
    data_lifetime_years: int | None = Field(default=None, ge=0)
    migration_time_years: float | None = Field(default=None, ge=0)
    retention_evidence: list[RetentionEvidence] | None = None


class ApplicationRequest(TrinetraModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=10_000)
    owner: str | None = Field(default=None, max_length=255)
    owner_email: str | None = Field(default=None, max_length=320)
    business_criticality: BusinessCriticality = BusinessCriticality.UNKNOWN
    data_classification: DataClassification = DataClassification.UNKNOWN
    exposure: ExposureLevel = ExposureLevel.UNKNOWN
    data_retention_years: int | None = Field(default=None, ge=0)
    migration_time_years: float | None = Field(default=None, ge=0)
    tags: list[str] = Field(default_factory=list)


class ApplicationResponse(ApplicationRequest):
    id: str
    project_id: str | None = None


class CsvImportRequest(TrinetraModel):
    """CMDB export body.  CSV is explicit rather than inferred from a file name."""

    csv_content: str = Field(min_length=1, max_length=10_000_000)


class ImportResponse(TrinetraModel):
    created: int = Field(ge=0)
    updated: int = Field(ge=0)
    skipped: int = Field(ge=0)
    errors: list[str] = Field(default_factory=list)


class RiskPresetRequest(TrinetraModel):
    planning_horizon_years: float | None = Field(default=None, ge=0, le=100)
    scenario: ResourceScenario = ResourceScenario.BASELINE
    rule_pack_toggles: dict[str, bool] = Field(default_factory=dict)


class RiskPresetResponse(RiskPresetRequest):
    version: str
    policy_version: str
    weights_version: str
    quantum_forecast_profile_version: str
    artefacts_rescored: int = Field(ge=0)
    recommendations_created: int = Field(ge=0)


class ReportCreateRequest(TrinetraModel):
    format: str = Field(min_length=1, max_length=32)


class ReportResponse(TrinetraModel):
    id: str
    scan_id: str
    format: str
    size_bytes: int | None = None
    checksum_sha256: str | None = None


class WhatIfRequest(TrinetraModel):
    z_years: float | None = Field(default=None, ge=0, le=100)
    x_years: int | None = Field(default=None, ge=0, le=100)
    scenario: ResourceScenario | None = None


class DashboardSummary(TrinetraModel):
    scan_count: int
    priority_counts: dict[str, int]
    needs_context_count: int
    worst_offenders: list[ArtefactListItem]


__all__ = [
    "ApplicationRequest",
    "ApplicationResponse",
    "ArtefactFacets",
    "ArtefactListItem",
    "ArtefactListResponse",
    "ContextPatchRequest",
    "CsvImportRequest",
    "DashboardSummary",
    "ImportResponse",
    "PageMeta",
    "ProjectCreateRequest",
    "ProjectResponse",
    "ReportCreateRequest",
    "ReportResponse",
    "RiskPresetRequest",
    "RiskPresetResponse",
    "ScanCreateRequest",
    "ScanListResponse",
    "ScanProgressResponse",
    "ScanResponse",
    "TokenRequest",
    "TokenResponse",
    "UserProvisionRequest",
    "UserResponse",
    "UserUpdateRequest",
    "WhatIfRequest",
]
