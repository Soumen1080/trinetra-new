"""Add Phase-8 project scoping, durable scan progress and audit records.

Revision ID: 0003_phase8_api_tenancy_progress
Revises: 0002_phase6_recommendation_evidence
Create Date: 2026-09-19
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0003_phase8_api_tenancy_progress"
down_revision: str | None = "0002_phase6_recommendation_evidence"
branch_labels: str | None = None
depends_on: str | None = None

JSONColumn = postgresql.JSONB().with_variant(sa.JSON(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_projects_tenant_name"),
    )
    op.create_index("ix_projects_tenant_id", "projects", ["tenant_id"])

    op.create_table(
        "project_memberships",
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("project_id", "user_id"),
    )
    op.create_index("ix_project_memberships_user_id", "project_memberships", ["user_id"])

    # Nullable initially keeps historical data readable.  The API requires a
    # project for all new writes; operators can backfill legacy records to a
    # chosen project during upgrade rather than silently guessing a tenant.
    # SQLite cannot add a foreign-key constraint with ALTER TABLE. Batch mode
    # rebuilds only these metadata tables there and emits ordinary ALTERs for
    # PostgreSQL.
    for table in ("applications", "scans", "org_setting_versions"):
        with op.batch_alter_table(table) as batch:
            batch.add_column(sa.Column("project_id", sa.String(length=64), nullable=True))
            batch.create_foreign_key(
                f"fk_{table}_project_id_projects",
                "projects",
                ["project_id"],
                ["id"],
                ondelete="CASCADE",
            )
            batch.create_index(f"ix_{table}_project_id", ["project_id"])
            if table == "applications":
                batch.add_column(sa.Column("provenance_json", JSONColumn, nullable=True))

    op.create_table(
        "scan_progress_events",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("percent", sa.Float(), nullable=False),
        sa.Column("stage", sa.String(length=64), nullable=False),
        sa.Column("counts_json", JSONColumn, nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("percent >= 0 AND percent <= 100", name="progress_in_range"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "sequence", name="uq_scan_progress_sequence"),
    )
    op.create_index(
        "ix_scan_progress_events_scan_id", "scan_progress_events", ["scan_id"]
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=True),
        sa.Column("actor_id", sa.String(length=64), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("details_json", JSONColumn, nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_project_id", "audit_logs", ["project_id"])
    op.create_index("ix_audit_logs_occurred_at", "audit_logs", ["occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_occurred_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_project_id", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_scan_progress_events_scan_id", table_name="scan_progress_events")
    op.drop_table("scan_progress_events")
    for table in ("org_setting_versions", "scans", "applications"):
        with op.batch_alter_table(table) as batch:
            if table == "applications":
                batch.drop_column("provenance_json")
            batch.drop_index(f"ix_{table}_project_id")
            batch.drop_constraint(f"fk_{table}_project_id_projects", type_="foreignkey")
            batch.drop_column("project_id")
    op.drop_index("ix_project_memberships_user_id", table_name="project_memberships")
    op.drop_table("project_memberships")
    op.drop_index("ix_projects_tenant_id", table_name="projects")
    op.drop_table("projects")
