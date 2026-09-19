"""SQLAlchemy tables (plan task 1.12).

The relational shape follows the architecture: an artefact belongs to one scan,
has one current context, and an **append-only** assessment history, with at most
one recommendation per assessment. Where the shape genuinely is variable -- the
original CBOM component -- a JSONB column preserves it without giving up
integrity elsewhere.

Enum columns are stored as ``String`` holding the canonical snake_case value
rather than as native PostgreSQL enums. Native enums require a migration to add
a value, which would make extending a vocabulary a schema change; the canonical
values are validated by Pydantic at the boundary regardless.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.models.base import Base, TimestampMixin
from app.models.enums import (
    AssessmentStatus,
    AssetType,
    BusinessCriticality,
    DataClassification,
    ExposureLevel,
    MoscaZBasis,
    NistSecurityLevel,
    Priority,
    QuantumProjectionStatus,
    QuantumVulnerability,
    ResourceScenario,
    ScanStatus,
    ScanTargetKind,
    UserRole,
)

#: JSONB on PostgreSQL, plain JSON elsewhere so the suite runs on SQLite.
JSONColumn = JSONB().with_variant(JSON(), "sqlite")


class User(Base, TimestampMixin):
    """Provisioned, single-tenant. Password hashes never reach a response model."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    email: Mapped[str | None] = mapped_column(String(320))
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(32), nullable=False, default=UserRole.VIEWER.value
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    scans: Mapped[list[Scan]] = relationship(back_populates="requester")

    __table_args__ = (Index("ix_users_username", "username"),)


class Project(Base, TimestampMixin):
    """A tenant-scoped workspace.

    A project is the authorization boundary for scans, inventory and settings.
    ``tenant_id`` is intentionally an opaque external identifier: deployments
    may map it to an IdP organisation, while a self-hosted install can simply
    use one value.  Data access is always checked through membership, never by
    trusting a project id supplied by the browser.
    """

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL")
    )

    memberships: Mapped[list[ProjectMembership]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_projects_tenant_name"),
        Index("ix_projects_tenant_id", "tenant_id"),
    )


class ProjectMembership(Base, TimestampMixin):
    """Explicit project access; global roles do not bypass tenant boundaries."""

    __tablename__ = "project_memberships"

    project_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )

    project: Mapped[Project] = relationship(back_populates="memberships")

    __table_args__ = (Index("ix_project_memberships_user_id", "user_id"),)


class Application(Base, TimestampMixin):
    """A system that owns artefacts; supplies business context (task 1.9)."""

    __tablename__ = "applications"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Nullable only to preserve pre-Phase-8 historical rows.  The API never
    # creates an unscoped application and the migration backfills old data.
    project_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("projects.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    owner: Mapped[str | None] = mapped_column(String(255))
    owner_email: Mapped[str | None] = mapped_column(String(320))

    business_criticality: Mapped[str] = mapped_column(
        String(32), nullable=False, default=BusinessCriticality.UNKNOWN.value
    )
    data_classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default=DataClassification.UNKNOWN.value
    )
    exposure: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ExposureLevel.UNKNOWN.value
    )

    # Nullable by design: absent means unevidenced, never zero (P3).
    data_retention_years: Mapped[int | None] = mapped_column(Integer)
    migration_time_years: Mapped[float | None] = mapped_column(Float)

    tags: Mapped[list | None] = mapped_column(JSONColumn)
    #: Per-field origin of supplied business context.  This prevents a CMDB
    #: import looking indistinguishable from a human-confirmed value (P4).
    provenance_json: Mapped[dict | None] = mapped_column(JSONColumn)

    __table_args__ = (
        Index("ix_applications_name", "name"),
        Index("ix_applications_project_id", "project_id"),
        CheckConstraint(
            "data_retention_years IS NULL OR data_retention_years >= 0",
            name="data_retention_non_negative",
        ),
        CheckConstraint(
            "migration_time_years IS NULL OR migration_time_years >= 0",
            name="migration_time_non_negative",
        ),
    )


class Scan(Base, TimestampMixin):
    """One target run. Re-scanning inserts a new row; nothing is overwritten."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("projects.id", ondelete="CASCADE")
    )
    target_kind: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ScanTargetKind.GIT_REPOSITORY.value
    )
    target_identifier: Mapped[str] = mapped_column(String(1024), nullable=False)
    target_reference: Mapped[str | None] = mapped_column(String(255))
    display_name: Mapped[str | None] = mapped_column(String(255))

    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ScanStatus.QUEUED.value
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    scanners_run: Mapped[list | None] = mapped_column(JSONColumn)
    tool_versions: Mapped[list | None] = mapped_column(JSONColumn)
    coverage_json: Mapped[dict | None] = mapped_column(JSONColumn)
    errors_json: Mapped[list | None] = mapped_column(JSONColumn)

    requested_by: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL")
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(255))

    requester: Mapped[User | None] = relationship(back_populates="scans")
    artefacts: Mapped[list[Artefact]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    progress_events: Mapped[list[ScanProgressEvent]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanProgressEvent.sequence",
    )

    __table_args__ = (
        Index("ix_scans_requested_by", "requested_by"),
        Index("ix_scans_project_id", "project_id"),
        Index("ix_scans_status", "status"),
        # Makes Idempotency-Key a database guarantee rather than an
        # application-level hope: a retried request cannot create a second scan.
        UniqueConstraint(
            "requested_by",
            "idempotency_key",
            name="uq_scans_requester_idempotency",
        ),
    )


class Artefact(Base, TimestampMixin):
    """One cryptographic asset found by one scan."""

    __tablename__ = "artefacts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    application_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("applications.id", ondelete="SET NULL")
    )

    type: Mapped[str] = mapped_column(
        String(32), nullable=False, default=AssetType.ALGORITHM.value
    )
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    #: Empty for libraries -- a package name is not an algorithm, and populating
    #: this would let the risk engine invent an attack model from a dependency.
    algorithm: Mapped[str | None] = mapped_column(String(255))
    oid: Mapped[str | None] = mapped_column(String(128))

    primitive: Mapped[str | None] = mapped_column(String(32))
    purpose: Mapped[list | None] = mapped_column(JSONColumn)

    key_size_bits: Mapped[int | None] = mapped_column(Integer)
    size_or_version: Mapped[str | None] = mapped_column(String(128))
    mode: Mapped[str | None] = mapped_column(String(32))
    padding: Mapped[str | None] = mapped_column(String(32))
    curve: Mapped[str | None] = mapped_column(String(64))

    quantum_vulnerability: Mapped[str] = mapped_column(
        String(32), nullable=False, default=QuantumVulnerability.UNKNOWN.value
    )
    nist_security_level: Mapped[str] = mapped_column(
        String(16), nullable=False, default=NistSecurityLevel.UNKNOWN.value
    )

    location: Mapped[str | None] = mapped_column(String(1024))
    used_for: Mapped[str | None] = mapped_column(Text)
    observed_data_category: Mapped[str | None] = mapped_column(String(128))
    discovered_by: Mapped[str] = mapped_column(String(32), nullable=False)

    detail_json: Mapped[dict | None] = mapped_column(JSONColumn)
    evidence_json: Mapped[list | None] = mapped_column(JSONColumn)
    #: The original CycloneDX component. Nothing a scanner produced is ever lost,
    #: even where Trinetra does not model it yet.
    raw_cbom: Mapped[dict | None] = mapped_column(JSONColumn)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="artefacts")
    context: Mapped[ArtefactContext | None] = relationship(
        back_populates="artefact", cascade="all, delete-orphan", uselist=False
    )
    assessments: Mapped[list[RiskAssessment]] = relationship(
        back_populates="artefact",
        cascade="all, delete-orphan",
        order_by="RiskAssessment.assessed_at.desc()",
    )
    review: Mapped[ArtefactReview | None] = relationship(
        back_populates="artefact", cascade="all, delete-orphan", uselist=False
    )

    __table_args__ = (
        Index("ix_artefacts_scan_id", "scan_id"),
        Index("ix_artefacts_name", "name"),
        Index("ix_artefacts_type", "type"),
        Index("ix_artefacts_application_id", "application_id"),
        CheckConstraint(
            "key_size_bits IS NULL OR key_size_bits > 0",
            name="key_size_positive",
        ),
        # The rule that keeps the risk engine honest, enforced at the storage
        # layer as well as in the Pydantic model.
        CheckConstraint(
            "type <> 'library' OR algorithm IS NULL",
            name="library_has_no_algorithm",
        ),
    )

    @property
    def latest_assessment(self) -> RiskAssessment | None:
        """Newest assessment. The relationship is ordered by ``assessed_at`` desc."""
        return self.assessments[0] if self.assessments else None


class ArtefactReview(Base, TimestampMixin):
    """Human disposition that follows an artefact independently of a scan run."""

    __tablename__ = "artefact_reviews"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    artefact_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("artefacts.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    owner: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str | None] = mapped_column(Text)
    updated_by: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL")
    )

    artefact: Mapped[Artefact] = relationship(back_populates="review")

    __table_args__ = (
        Index("ix_artefact_reviews_project_id", "project_id"),
        Index("ix_artefact_reviews_status", "status"),
    )


class ArtefactContext(Base, TimestampMixin):
    """Current, editable business context for one artefact, with provenance."""

    __tablename__ = "artefact_contexts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    artefact_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("artefacts.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    application_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("applications.id", ondelete="SET NULL")
    )

    business_criticality: Mapped[str] = mapped_column(
        String(32), nullable=False, default=BusinessCriticality.UNKNOWN.value
    )
    data_classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default=DataClassification.UNKNOWN.value
    )
    exposure: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ExposureLevel.UNKNOWN.value
    )
    data_category: Mapped[str | None] = mapped_column(String(128))

    data_lifetime_years: Mapped[int | None] = mapped_column(Integer)
    migration_time_years: Mapped[float | None] = mapped_column(Float)

    retention_evidence_json: Mapped[list | None] = mapped_column(JSONColumn)
    #: field name -> {tier, source_detail}. A field absent here was never
    #: resolved and must render as unknown (P4).
    provenance_json: Mapped[dict | None] = mapped_column(JSONColumn)

    updated_by: Mapped[str | None] = mapped_column(String(64))

    artefact: Mapped[Artefact] = relationship(back_populates="context")

    __table_args__ = (
        Index("ix_artefact_contexts_artefact_id", "artefact_id"),
        CheckConstraint(
            "data_lifetime_years IS NULL OR data_lifetime_years >= 0",
            name="lifetime_non_negative",
        ),
    )


class RiskAssessment(Base):
    """**Append-only.** Rows are inserted, never updated (P5).

    Intentionally omits :class:`TimestampMixin`: an ``updated_at`` column would
    imply an update path that must not exist. ``artefact.latest_assessment``
    returns the newest row.
    """

    __tablename__ = "risk_assessments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    artefact_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("artefacts.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("scans.id", ondelete="SET NULL")
    )

    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=AssessmentStatus.NEEDS_CONTEXT.value
    )
    final_score: Mapped[float | None] = mapped_column(Float)
    final_confidence: Mapped[str | None] = mapped_column(String(16))
    priority: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Priority.NONE.value
    )

    # -- Track A: Mosca --------------------------------------------------
    mosca_x_years: Mapped[int | None] = mapped_column(Integer)
    mosca_y_years: Mapped[float | None] = mapped_column(Float)
    mosca_z_years: Mapped[float | None] = mapped_column(Float)
    mosca_z_basis: Mapped[str] = mapped_column(
        String(32), nullable=False, default=MoscaZBasis.UNAVAILABLE.value
    )
    mosca_is_urgent: Mapped[bool | None] = mapped_column(Boolean)
    mosca_shortfall_years: Mapped[float | None] = mapped_column(Float)
    mosca_evidence_json: Mapped[list | None] = mapped_column(JSONColumn)

    # -- Track B: quantum resource ---------------------------------------
    resource_m_years: Mapped[float | None] = mapped_column(Float)
    resource_scenario: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ResourceScenario.BASELINE.value
    )
    resource_assumptions_json: Mapped[dict | None] = mapped_column(JSONColumn)
    attack_threshold_json: Mapped[dict | None] = mapped_column(JSONColumn)
    forecast_capability_json: Mapped[dict | None] = mapped_column(JSONColumn)
    projected_break_year: Mapped[int | None] = mapped_column(Integer)
    migration_deadline_year: Mapped[int | None] = mapped_column(Integer)
    quantum_projection_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=QuantumProjectionStatus.MODEL_UNAVAILABLE.value,
    )

    # -- Combination ------------------------------------------------------
    score_contributions_json: Mapped[list | None] = mapped_column(JSONColumn)
    missing_fields_json: Mapped[list | None] = mapped_column(JSONColumn)
    input_provenance_json: Mapped[dict | None] = mapped_column(JSONColumn)
    rationale: Mapped[str | None] = mapped_column(Text)

    # -- Versions: what makes a verdict reproducible ----------------------
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    weights_version: Mapped[str] = mapped_column(String(64), nullable=False)
    quantum_forecast_profile_version: Mapped[str | None] = mapped_column(String(64))

    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    artefact: Mapped[Artefact] = relationship(back_populates="assessments")
    recommendation: Mapped[Recommendation | None] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", uselist=False
    )

    __table_args__ = (
        Index("ix_risk_assessments_artefact_id", "artefact_id"),
        Index("ix_risk_assessments_priority", "priority"),
        Index("ix_risk_assessments_assessed_at", "assessed_at"),
        CheckConstraint(
            "final_score IS NULL OR (final_score >= 0 AND final_score <= 100)",
            name="score_in_range",
        ),
        # A score without the 'scored' status, or 'scored' without a score,
        # would let an unmeasured artefact be ranked as if it had been measured.
        CheckConstraint(
            "(status = 'scored' AND final_score IS NOT NULL) "
            "OR (status <> 'scored' AND final_score IS NULL)",
            name="score_matches_status",
        ),
        CheckConstraint(
            "final_score IS NOT NULL OR priority = 'none'",
            name="unscored_has_no_priority",
        ),
    )


class Recommendation(Base, TimestampMixin):
    """At most one per assessment (unique FK)."""

    __tablename__ = "recommendations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("risk_assessments.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    recommended_algorithm: Mapped[str | None] = mapped_column(String(255))
    recommended_parameter_set: Mapped[str | None] = mapped_column(String(128))
    security_category: Mapped[int | None] = mapped_column(Integer)
    classical_partner: Mapped[str | None] = mapped_column(String(128))
    is_hybrid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requires_manual_review: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    rationale: Mapped[str | None] = mapped_column(Text)
    # Always NULL for schema-v2 recommendations: deployment fit is measured,
    # not derived from published FIPS object sizes.
    fit_score: Mapped[float | None] = mapped_column(Float)
    fit_breakdown_json: Mapped[dict | None] = mapped_column(JSONColumn)
    latency_impact_json: Mapped[dict | None] = mapped_column(JSONColumn)
    cost_estimate_json: Mapped[dict | None] = mapped_column(JSONColumn)
    migration_wave: Mapped[int | None] = mapped_column(Integer)

    profile_version: Mapped[str | None] = mapped_column(String(64))

    assessment: Mapped[RiskAssessment] = relationship(back_populates="recommendation")

    __table_args__ = (Index("ix_recommendations_assessment_id", "assessment_id"),)


class DependencyEdge(Base, TimestampMixin):
    """Graph edges: application -> library -> algorithm (task 1.10)."""

    __tablename__ = "dependency_edges"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("scans.id", ondelete="CASCADE")
    )

    source_id: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    target_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    relation: Mapped[str] = mapped_column(String(32), nullable=False)
    is_direct: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("ix_dependency_edges_source_id", "source_id"),
        Index("ix_dependency_edges_target_id", "target_id"),
        Index("ix_dependency_edges_scan_id", "scan_id"),
        UniqueConstraint(
            "scan_id",
            "source_id",
            "target_id",
            "relation",
            name="uq_dependency_edges_edge",
        ),
        CheckConstraint("source_id <> target_id", name="no_self_edge"),
    )


class OrgSettingVersion(Base, TimestampMixin):
    """Immutable configuration versions; exactly one active.

    Versioned rather than mutable because changing a policy re-scores every
    artefact, and a verdict must remain traceable to the policy that produced it.
    """

    __tablename__ = "org_setting_versions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("projects.id", ondelete="CASCADE")
    )
    version: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    settings_json: Mapped[dict] = mapped_column(JSONColumn, nullable=False)
    policy_version: Mapped[str | None] = mapped_column(String(64))
    weights_version: Mapped[str | None] = mapped_column(String(64))
    quantum_forecast_profile_version: Mapped[str | None] = mapped_column(String(64))

    created_by: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        Index("ix_org_setting_versions_active", "is_active"),
        Index("ix_org_setting_versions_project_id", "project_id"),
    )


class Report(Base, TimestampMixin):
    """A generated CBOM / PDF artefact reference."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    storage_path: Mapped[str | None] = mapped_column(String(1024))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    checksum_sha256: Mapped[str | None] = mapped_column(String(64))

    requested_by: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL")
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(255))

    __table_args__ = (
        Index("ix_reports_scan_id", "scan_id"),
        UniqueConstraint(
            "requested_by",
            "idempotency_key",
            name="uq_reports_requester_idempotency",
        ),
    )


class ScanProgressEvent(Base):
    """Durable progress and log events for polling/SSE/WebSocket fallback.

    Redis pub/sub remains the low-latency delivery path in production, but an
    event row makes progress recoverable after a browser reconnect or a Redis
    interruption.  Counts are a JSON object so scanners can report discovered
    files, scanned files and findings without a fragile fixed schema.
    """

    __tablename__ = "scan_progress_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    percent: Mapped[float] = mapped_column(Float, nullable=False)
    stage: Mapped[str] = mapped_column(String(64), nullable=False)
    counts_json: Mapped[dict | None] = mapped_column(JSONColumn)
    message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="progress_events")

    __table_args__ = (
        UniqueConstraint("scan_id", "sequence", name="uq_scan_progress_sequence"),
        Index("ix_scan_progress_events_scan_id", "scan_id"),
        CheckConstraint("percent >= 0 AND percent <= 100", name="progress_in_range"),
    )


class AuditLog(Base):
    """Append-only record of every API mutation (Phase 8.13)."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("projects.id", ondelete="SET NULL")
    )
    actor_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(64))
    details_json: Mapped[dict | None] = mapped_column(JSONColumn)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_audit_logs_project_id", "project_id"),
        Index("ix_audit_logs_occurred_at", "occurred_at"),
    )


__all__ = [
    "Application",
    "Artefact",
    "ArtefactContext",
    "AuditLog",
    "DependencyEdge",
    "OrgSettingVersion",
    "Project",
    "ProjectMembership",
    "Recommendation",
    "Report",
    "RiskAssessment",
    "Scan",
    "ScanProgressEvent",
    "User",
]
