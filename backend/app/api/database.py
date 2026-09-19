"""Database wiring kept outside routers so tests can inject a session factory."""

from __future__ import annotations

import os
from collections.abc import Generator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.models.base import Base


def database_url() -> str:
    """Return the configured database URL without baking credentials into code."""
    return os.getenv("TRINETRA_DATABASE_URL", "sqlite:///./trinetra.db")


def make_engine(url: str | None = None) -> Engine:
    resolved = url or database_url()
    kwargs: dict[str, object] = {"future": True, "pool_pre_ping": True}
    if resolved.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(resolved, **kwargs)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, future=True, expire_on_commit=False)


def initialise_database(engine: Engine) -> None:
    """Create tables for development/test installs; production uses Alembic."""
    Base.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    """Dependency placeholder overridden by :func:`create_app` at startup."""
    raise RuntimeError("database dependency was not configured")


__all__ = [
    "database_url",
    "get_session",
    "initialise_database",
    "make_engine",
    "make_session_factory",
]
