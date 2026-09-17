"""Alembic environment.

The database URL comes from ``TRINETRA_DATABASE_URL`` rather than ``alembic.ini``
so that credentials are never committed (P7: nothing leaves the private network,
and nothing sensitive enters the repository).
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.models.base import Base

# Importing the tables module registers every table on Base.metadata, which is
# what autogenerate compares against.
from app.models import tables  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

DEFAULT_URL = "postgresql+psycopg://trinetra:trinetra@localhost:5433/trinetra"

#: Precedence: a URL set programmatically by the caller (the test suite does
#: this) wins, then the environment, then the development default. The
#: placeholder in alembic.ini is treated as unset -- it exists only because
#: Alembic requires the key to be present.
_configured = config.get_main_option("sqlalchemy.url", "")
if not _configured or _configured.startswith("driver://"):
    config.set_main_option(
        "sqlalchemy.url", os.getenv("TRINETRA_DATABASE_URL", DEFAULT_URL)
    )

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
