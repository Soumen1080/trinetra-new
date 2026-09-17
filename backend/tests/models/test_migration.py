"""The migration must produce the same schema the models declare.

Without this, the tests pass against ``create_all`` while a real deployment runs
a stale migration -- and the two only diverge in production.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect

from app.models import tables  # noqa: F401  (registers the tables)
from app.models.base import Base

BACKEND_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def alembic_config(tmp_path: Path) -> Config:
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'test.db'}")
    return config


def test_single_head_revision(alembic_config: Config) -> None:
    """Two heads mean an unmerged branch, and an ambiguous upgrade target."""
    script = ScriptDirectory.from_config(alembic_config)
    assert len(script.get_heads()) == 1


def test_migration_creates_every_model_table(
    alembic_config: Config, tmp_path: Path
) -> None:
    from alembic import command

    command.upgrade(alembic_config, "head")

    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    migrated = set(inspect(engine).get_table_names()) - {"alembic_version"}
    engine.dispose()

    assert migrated == set(Base.metadata.tables)


def test_migration_matches_model_columns(
    alembic_config: Config, tmp_path: Path
) -> None:
    """Column-level parity, so a model field added without a migration fails here."""
    from alembic import command

    command.upgrade(alembic_config, "head")

    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    inspector = inspect(engine)
    mismatches: list[str] = []

    for table_name, table in Base.metadata.tables.items():
        migrated = {c["name"] for c in inspector.get_columns(table_name)}
        declared = {c.name for c in table.columns}
        if migrated != declared:
            missing = declared - migrated
            extra = migrated - declared
            mismatches.append(f"{table_name}: missing={missing} extra={extra}")

    engine.dispose()
    assert not mismatches, "migration drifted from models: " + "; ".join(mismatches)


def test_downgrade_removes_every_table(
    alembic_config: Config, tmp_path: Path
) -> None:
    from alembic import command

    command.upgrade(alembic_config, "head")
    command.downgrade(alembic_config, "base")

    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    remaining = set(inspect(engine).get_table_names()) - {"alembic_version"}
    engine.dispose()

    assert not remaining
