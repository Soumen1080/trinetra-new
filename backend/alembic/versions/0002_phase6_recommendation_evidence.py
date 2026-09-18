"""Persist Phase-6 recommendation evidence without a synthetic fit score.

Revision ID: 0002_phase6_recommendation_evidence
Revises: 0001_initial_schema
Create Date: 2026-09-18
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "0002_phase6_recommendation_evidence"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "recommendations", sa.Column("security_category", sa.Integer(), nullable=True)
    )
    op.add_column(
        "recommendations",
        sa.Column("classical_partner", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "recommendations", sa.Column("fit_score", sa.Float(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("recommendations", "fit_score")
    op.drop_column("recommendations", "classical_partner")
    op.drop_column("recommendations", "security_category")
