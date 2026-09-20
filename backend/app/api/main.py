"""FastAPI application factory and uniform transport-level safeguards."""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.database import initialise_database, make_engine, make_session_factory
from app.api.routes import router, scan_websocket
from app.api.security import hash_password
from app.models import tables
from app.services.observability import MetricsMiddleware, metrics
from app.services.scan_orchestrator import CeleryScanDispatcher, ScanDispatcher
from app.services.security import RedactingFormatter, SecurityHeadersMiddleware

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """A small bounded fixed-window limiter for API instances.

    Production deployments should put the same policy at the edge/Redis as
    well; this local guard still protects a single-process development or
    on-premise install and keeps limits testable without external services.
    """

    def __init__(self, app: Any, *, requests_per_minute: int) -> None:
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Any:
        if request.url.path in {"/health", "/docs", "/openapi.json", "/redoc"}:
            return await call_next(request)
        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        with self._lock:
            entries = self._requests[client]
            while entries and entries[0] <= now - 60:
                entries.popleft()
            if len(entries) >= self.requests_per_minute:
                return JSONResponse(
                    status_code=429,
                    content={
                        "code": "RATE_LIMITED",
                        "message": "Too many requests; try again shortly.",
                    },
                )
            entries.append(now)
        return await call_next(request)


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Any:
        request.state.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response


def _origins() -> list[str]:
    configured = os.getenv("TRINETRA_CORS_ORIGINS", "http://localhost:5173")
    return [item.strip() for item in configured.split(",") if item.strip()]


def _bootstrap(session_factory: sessionmaker[Session]) -> None:
    """Provision only an explicitly configured first administrator."""
    username = os.getenv("BOOTSTRAP_ADMIN_USERNAME")
    password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD")
    if not username or not password:
        return
    with session_factory() as session:
        if session.scalar(select(tables.User.id).where(tables.User.username == username)):
            return
        user = tables.User(
            id=str(uuid.uuid4()),
            username=username,
            password_hash=hash_password(password),
            role="admin",
        )
        project = tables.Project(
            id=str(uuid.uuid4()),
            tenant_id=os.getenv("BOOTSTRAP_TENANT_ID", "default"),
            name=os.getenv("BOOTSTRAP_PROJECT_NAME", "Default project"),
            created_by=user.id,
        )
        session.add_all(
            [
                user,
                project,
                tables.ProjectMembership(project_id=project.id, user_id=user.id),
            ]
        )
        session.commit()
        logger.warning(
            "Bootstrap administrator provisioned; remove the bootstrap password "
            "from the environment."
        )


def create_app(
    *,
    engine: Engine | None = None,
    session_factory: sessionmaker[Session] | None = None,
    scan_dispatcher: ScanDispatcher | None = None,
    initialise_schema: bool | None = None,
    report_store: str | Path | None = None,
) -> FastAPI:
    """Build an injectable application for production, tests and the CLI."""
    if session_factory is None:
        resolved_engine = engine or make_engine()
        session_factory = make_session_factory(resolved_engine)
    else:
        resolved_engine = engine
    should_initialise = initialise_schema
    if should_initialise is None:
        should_initialise = (
            os.getenv("TRINETRA_AUTO_CREATE_SCHEMA", "true").lower() == "true"
        )
    if should_initialise and resolved_engine is not None:
        initialise_database(resolved_engine)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        # Configure redacting formatter on root logger handlers
        for handler in logging.root.handlers:
            if handler.formatter:
                handler.setFormatter(RedactingFormatter(handler.formatter._fmt))
            else:
                handler.setFormatter(RedactingFormatter())
        _bootstrap(session_factory)
        yield

    app = FastAPI(
        title="Trinetra API",
        version="0.1.0",
        description=(
            "Project-scoped cryptographic inventory, quantum-risk and migration API."
        ),
        lifespan=lifespan,
    )
    app.state.session_factory = session_factory
    app.state.scan_dispatcher = scan_dispatcher or CeleryScanDispatcher()
    app.state.report_store = str(
        report_store or os.getenv("TRINETRA_REPORT_STORE", "./reports")
    )

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Idempotency-Key",
            "X-CSRF-Token",
            "X-Project-ID",
            "X-Request-ID",
        ],
    )
    app.add_middleware(
        RateLimitMiddleware,
        requests_per_minute=int(os.getenv("TRINETRA_RATE_LIMIT_PER_MINUTE", "120")),
    )
    app.add_middleware(RequestIdMiddleware)

    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        request: Request, error: HTTPException
    ) -> JSONResponse:
        detail = error.detail if isinstance(error.detail, dict) else None
        content = detail or {"code": "INVALID_REQUEST", "message": str(error.detail)}
        response = JSONResponse(status_code=error.status_code, content=content)
        if hasattr(request.state, "request_id"):
            response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, error: RequestValidationError
    ) -> JSONResponse:
        response = JSONResponse(
            status_code=422,
            content={
                "code": "VALIDATION_ERROR",
                "message": "Request validation failed.",
                "details": error.errors(),
            },
        )
        if hasattr(request.state, "request_id"):
            response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(Exception)
    async def internal_exception_handler(
        request: Request, error: Exception
    ) -> JSONResponse:
        logger.exception("Unhandled API exception", exc_info=error)
        response = JSONResponse(
            status_code=500,
            content={
                "code": "INTERNAL_ERROR",
                "message": "The request could not be completed.",
            },
        )
        if hasattr(request.state, "request_id"):
            response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.get("/health", tags=["ops"])
    def health() -> dict[str, Any]:
        db_status = "ok"
        try:
            with session_factory() as session:
                session.execute(select(1)).scalar()
        except Exception:
            db_status = "degraded"
        return {
            "status": "ok" if db_status == "ok" else "degraded",
            "components": {
                "database": db_status,
                "api": "ok",
            },
        }

    @app.get("/health/ready", tags=["ops"])
    def health_ready(response: Response) -> dict[str, str]:
        try:
            with session_factory() as session:
                session.execute(select(1)).scalar()
            return {"status": "ready"}
        except Exception as error:
            response.status_code = 503
            return {"status": "not_ready", "reason": str(error)}

    @app.get("/health/live", tags=["ops"])
    def health_live() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/metrics", tags=["ops"])
    def prometheus_metrics() -> Response:
        body = metrics.generate_prometheus_text()
        return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")

    app.include_router(router)
    app.websocket("/ws/scans/{scan_id}")(scan_websocket)
    return app


app = create_app()


__all__ = ["app", "create_app"]
