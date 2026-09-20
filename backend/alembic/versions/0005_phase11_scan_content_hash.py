"""Add content_hash to scans for artefact caching and incremental rescan.

Revision ID: 0005_phase11_scan_content_hash
Revises: 0004_phase9_artefact_reviews
Create Date: 2026-09-20
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0005_phase11_scan_content_hash"
down_revision: str | None = "0004_phase9_artefact_reviews"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("content_hash", sa.String(length=128), nullable=True))
    op.create_index("ix_scans_content_hash", "scans", ["content_hash"])


def downgrade() -> None:
    op.drop_index("ix_scans_content_hash", table_name="scans")
    op.drop_column("scans", "content_hash")
