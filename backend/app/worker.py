"""Celery worker entry point for scan execution.

Run with ``celery -A app.worker.celery_app worker``.  The task receives only a
scan id; target credentials and scanner secrets stay in their private services.
"""

from __future__ import annotations

import os

from celery import Celery

from app.api.database import make_engine, make_session_factory
from app.services.scan_orchestrator import execute_scan

celery_app = Celery(
    "trinetra",
    broker=os.getenv("TRINETRA_CELERY_BROKER_URL", "redis://redis:6379/0"),
    backend=os.getenv("TRINETRA_CELERY_RESULT_BACKEND", "redis://redis:6379/0"),
)
celery_app.conf.update(
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    worker_concurrency=int(os.getenv("TRINETRA_WORKER_CONCURRENCY", "4")),
    task_time_limit=int(os.getenv("TRINETRA_TASK_TIME_LIMIT", "3600")),
    task_soft_time_limit=int(os.getenv("TRINETRA_TASK_SOFT_TIME_LIMIT", "3300")),
)


@celery_app.task(name="trinetra.execute_scan", bind=True, acks_late=True)
def execute_scan_task(self, scan_id: str) -> None:  # type: ignore[no-untyped-def]
    """Execute one idempotent scan lifecycle in a worker process."""
    engine = make_engine()
    try:
        execute_scan(make_session_factory(engine), scan_id)
    finally:
        engine.dispose()


__all__ = ["celery_app", "execute_scan_task"]
