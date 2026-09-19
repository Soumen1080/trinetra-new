"""Add persistent analyst review dispositions for Phase 9 bulk actions.

Revision ID: 0004_phase9_artefact_reviews
Revises: 0003_phase8_api_tenancy_progress
Create Date: 2026-09-19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "0004_phase9_artefact_reviews"
down_revision: str | None = "0003_phase8_api_tenancy_progress"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "artefact_reviews",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("artefact_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("owner", sa.String(length=255), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("updated_by", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artefact_id"], ["artefacts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["updated_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artefact_id"),
    )
    op.create_index("ix_artefact_reviews_project_id", "artefact_reviews", ["project_id"])
    op.create_index("ix_artefact_reviews_status", "artefact_reviews", ["status"])


def downgrade() -> None:
    op.drop_index("ix_artefact_reviews_status", table_name="artefact_reviews")
    op.drop_index("ix_artefact_reviews_project_id", table_name="artefact_reviews")
    op.drop_table("artefact_reviews")
