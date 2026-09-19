"""Phase-8 HTTP, SSE and WebSocket routes.

Routers coordinate validated requests and repository calls only.  Engines remain
pure and the repository remains the sole database access boundary.
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import secrets
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.api.dependencies import get_db
from app.api.presenters import (
    artefact_item,
    progress_response,
    scan_response,
    scan_result_from_rows,
)
from app.api.schemas import (
    ApplicationRequest,
    ApplicationResponse,
    ArtefactFacets,
    ArtefactListResponse,
    BulkReviewRequest,
    BulkReviewResponse,
    ContextPatchRequest,
    CsvImportRequest,
    DashboardApplication,
    DashboardSummary,
    DashboardTrendPoint,
    ImportResponse,
    PageMeta,
    ProjectCreateRequest,
    ProjectResponse,
    ReportCreateRequest,
    ReportResponse,
    RiskPresetRequest,
    RiskPresetResponse,
    ScanCreateRequest,
    ScanListResponse,
    ScanProgressResponse,
    ScanResponse,
    SessionResponse,
    TokenRequest,
    TokenResponse,
    UserProvisionRequest,
    UserResponse,
    UserUpdateRequest,
    WhatIfRequest,
)
from app.api.security import (
    Principal,
    create_access_token,
    current_principal,
    current_project,
    decode_access_token,
    hash_password,
    require_mutation,
    require_roles,
    verify_password,
)
from app.engines.final_risk_engine import RiskSettings, classify_risk
from app.engines.profiles.loader import load_risk_profiles
from app.exporters import ExportFormat, export
from app.models import tables
from app.models.base import utcnow
from app.models.enums import AssessmentStatus, ProvenanceTier, ScanStatus, UserRole
from app.repositories import (
    append_assessment,
    application_for_project,
    applications_for_project,
    artefact_for_project,
    artefacts_for_scan,
    progress_since,
    project_for_user,
    projects_for_user,
    scan_for_project,
    scans_for_project,
    write_audit_log,
)
from app.schemas.common import Provenance
from app.schemas.context import ArtefactContext
from app.schemas.mapping import (
    artefact_from_row,
    assessment_from_row,
    context_from_row,
    context_to_row,
    recommendation_from_row,
)
from app.services.risk_assessment import apply_risk_settings_and_rescore
from app.services.scan_orchestrator import QueueUnavailableError, publish_progress

router = APIRouter(prefix="/api")
Db = Annotated[Session, Depends(get_db)]
Reader = Annotated[Principal, Depends(current_principal)]
Analyst = Annotated[
    Principal, Depends(require_mutation(UserRole.ADMIN, UserRole.ANALYST))
]
Admin = Annotated[Principal, Depends(require_mutation(UserRole.ADMIN))]


def _not_found(noun: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"code": "NOT_FOUND", "message": f"{noun} was not found."},
    )


def _audit(
    session: Session,
    request: Request,
    *,
    principal: Principal | None,
    project_id: str | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    details: dict[str, object] | None = None,
) -> None:
    write_audit_log(
        session,
        entry_id=str(uuid.uuid4()),
        project_id=project_id,
        actor_id=principal.user.id if principal else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        request_id=getattr(request.state, "request_id", None),
        details=details,
        occurred_at=utcnow(),
    )


def _project(request: Request, principal: Principal) -> tables.Project:
    """Use the dependency logic while keeping one readable signature per route."""
    return current_project(request, principal)


def _user_response(user: tables.User) -> UserResponse:
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=UserRole(user.role),
        is_active=user.is_active,
    )


def _application_response(row: tables.Application) -> ApplicationResponse:
    return ApplicationResponse(
        id=row.id,
        project_id=row.project_id,
        name=row.name,
        description=row.description,
        owner=row.owner,
        owner_email=row.owner_email,
        business_criticality=row.business_criticality,
        data_classification=row.data_classification,
        exposure=row.exposure,
        data_retention_years=row.data_retention_years,
        migration_time_years=row.migration_time_years,
        tags=list(row.tags or []),
    )


def _scan_with_count(session: Session, row: tables.Scan) -> ScanResponse:
    count = int(
        session.scalar(
            select(func.count())
            .select_from(tables.Artefact)
            .where(tables.Artefact.scan_id == row.id)
        )
        or 0
    )
    return scan_response(row, artefact_count=count)


def _latest(item: tables.Artefact) -> tables.RiskAssessment | None:
    return item.latest_assessment


def _filter_artefacts(
    rows: list[tables.Artefact],
    *,
    asset_type: str | None,
    priority: str | None,
    application_id: str | None,
    algorithm: str | None,
    quantum_status: str | None,
    scanner: str | None,
    search: str | None,
) -> list[tables.Artefact]:
    allowed_priorities = {
        item.strip() for item in (priority or "").split(",") if item.strip()
    }
    needle = search.casefold().strip() if search else ""
    result: list[tables.Artefact] = []
    for row in rows:
        assessment = _latest(row)
        if asset_type and row.type != asset_type:
            continue
        if (
            allowed_priorities
            and (assessment.priority if assessment else "none") not in allowed_priorities
        ):
            continue
        if application_id and row.application_id != application_id:
            continue
        if algorithm and (row.algorithm or "").casefold() != algorithm.casefold():
            continue
        if quantum_status and row.quantum_vulnerability != quantum_status:
            continue
        if scanner and row.discovered_by != scanner:
            continue
        if (
            needle
            and needle
            not in " ".join(
                filter(None, (row.name, row.algorithm, row.location, row.used_for))
            ).casefold()
        ):
            continue
        result.append(row)
    priority_rank = {"p0": 0, "p1": 1, "p2": 2, "none": 3}
    # UI default is risk descending; unassessed findings remain visible after
    # scored findings rather than being falsely labelled low risk.
    result.sort(
        key=lambda row: (
            priority_rank.get(_latest(row).priority if _latest(row) else "none", 4),
            -(_latest(row).final_score or -1) if _latest(row) else 1,
            row.name.casefold(),
        )
    )
    return result


def _facets(rows: list[tables.Artefact]) -> ArtefactFacets:
    values: dict[str, dict[str, int]] = {
        "type": {},
        "priority": {},
        "application": {},
        "algorithm": {},
        "quantum_status": {},
        "scanner": {},
    }
    for row in rows:
        pairs = {
            "type": row.type,
            "priority": _latest(row).priority if _latest(row) else "none",
            "application": row.application_id or "unassigned",
            "algorithm": row.algorithm or "unknown",
            "quantum_status": row.quantum_vulnerability,
            "scanner": row.discovered_by,
        }
        for key, value in pairs.items():
            values[key][value] = values[key].get(value, 0) + 1
    return ArtefactFacets(**values)


def _artefact_query_response(
    rows: list[tables.Artefact],
    *,
    offset: int,
    limit: int,
    scan_status: ScanStatus | None = None,
) -> ArtefactListResponse:
    return ArtefactListResponse(
        items=[artefact_item(row) for row in rows[offset : offset + limit]],
        page=PageMeta(offset=offset, limit=limit, total=len(rows)),
        facets=_facets(rows),
        scan_status=scan_status,
        partial_results=scan_status in {ScanStatus.QUEUED, ScanStatus.RUNNING},
    )


# ---------------------------------------------------------------------------
# Auth, administration and project selection
# ---------------------------------------------------------------------------


@router.post("/auth/login", response_model=TokenResponse)
def login(payload: TokenRequest, response: Response, session: Db) -> TokenResponse:
    user = session.scalar(
        select(tables.User).where(tables.User.username == payload.username)
    )
    if (
        user is None
        or not user.is_active
        or not verify_password(payload.password, user.password_hash)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "UNAUTHENTICATED",
                "message": "Invalid username or password.",
            },
        )
    token = create_access_token(user)
    csrf = secrets.token_urlsafe(32)
    response.set_cookie(
        "trinetra_access_token",
        token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=28_800,
    )
    response.set_cookie(
        "trinetra_csrf_token",
        csrf,
        httponly=False,
        secure=False,
        samesite="strict",
        max_age=28_800,
    )
    return TokenResponse(
        access_token=token,
        expires_in=28_800,
        csrf_token=csrf,
        user=_user_response(user),
    )


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response) -> None:
    response.delete_cookie("trinetra_access_token")
    response.delete_cookie("trinetra_csrf_token")


@router.get("/auth/me", response_model=UserResponse)
def me(principal: Reader) -> UserResponse:
    return _user_response(principal.user)


@router.get("/auth/session", response_model=SessionResponse)
def session_restore(
    response: Response, principal: Reader
) -> SessionResponse:
    """Restore a cookie-authenticated browser session with a fresh CSRF token.

    The access token remains HttpOnly; the short-lived anti-CSRF value is held
    only in the running client after this response.
    """
    csrf = secrets.token_urlsafe(32)
    response.set_cookie(
        "trinetra_csrf_token",
        csrf,
        httponly=False,
        secure=False,
        samesite="strict",
        max_age=28_800,
    )
    return SessionResponse(csrf_token=csrf, user=_user_response(principal.user))


@router.get("/projects", response_model=list[ProjectResponse])
def list_projects(principal: Reader, session: Db) -> list[ProjectResponse]:
    return [
        ProjectResponse(
            id=row.id, tenant_id=row.tenant_id, name=row.name, description=row.description
        )
        for row in projects_for_user(session, user_id=principal.user.id)
    ]


@router.post(
    "/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED
)
def create_project(
    payload: ProjectCreateRequest, request: Request, principal: Admin, session: Db
) -> ProjectResponse:
    row = tables.Project(
        id=str(uuid.uuid4()),
        tenant_id=payload.tenant_id,
        name=payload.name,
        description=payload.description,
        created_by=principal.user.id,
    )
    session.add(row)
    session.add(tables.ProjectMembership(project_id=row.id, user_id=principal.user.id))
    _audit(
        session,
        request,
        principal=principal,
        project_id=row.id,
        action="project.create",
        resource_type="project",
        resource_id=row.id,
    )
    session.commit()
    return ProjectResponse(
        id=row.id, tenant_id=row.tenant_id, name=row.name, description=row.description
    )


@router.get("/admin/users", response_model=list[UserResponse])
def list_users(
    _: Annotated[Principal, Depends(require_roles(UserRole.ADMIN))], session: Db
) -> list[UserResponse]:
    return [
        _user_response(row)
        for row in session.scalars(select(tables.User).order_by(tables.User.username))
    ]


@router.post(
    "/admin/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
def provision_user(
    payload: UserProvisionRequest, request: Request, principal: Admin, session: Db
) -> UserResponse:
    if session.scalar(
        select(tables.User.id).where(tables.User.username == payload.username)
    ):
        raise HTTPException(
            status_code=409,
            detail={"code": "CONFLICT", "message": "Username already exists."},
        )
    try:
        password_hash = hash_password(payload.password)
    except ValueError as error:
        raise HTTPException(
            status_code=400, detail={"code": "INVALID_REQUEST", "message": str(error)}
        ) from error
    user = tables.User(
        id=str(uuid.uuid4()),
        username=payload.username,
        email=payload.email,
        password_hash=password_hash,
        role=payload.role.value,
    )
    session.add(user)
    project_ids = payload.project_ids or [
        project.id for project in projects_for_user(session, user_id=principal.user.id)
    ]
    for project_id in project_ids:
        if (
            project_for_user(session, project_id=project_id, user_id=principal.user.id)
            is None
        ):
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "FORBIDDEN",
                    "message": "Cannot provision access outside your projects.",
                },
            )
        session.add(tables.ProjectMembership(project_id=project_id, user_id=user.id))
    _audit(
        session,
        request,
        principal=principal,
        project_id=None,
        action="user.provision",
        resource_type="user",
        resource_id=user.id,
    )
    session.commit()
    return _user_response(user)


@router.patch("/admin/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: str,
    payload: UserUpdateRequest,
    request: Request,
    principal: Admin,
    session: Db,
) -> UserResponse:
    user = session.get(tables.User, user_id)
    if user is None:
        raise _not_found("User")
    if payload.role is not None:
        user.role = payload.role.value
    if payload.is_active is not None:
        user.is_active = payload.is_active
    _audit(
        session,
        request,
        principal=principal,
        project_id=None,
        action="user.update",
        resource_type="user",
        resource_id=user.id,
    )
    session.commit()
    return _user_response(user)


# ---------------------------------------------------------------------------
# Scan lifecycle, progress and inventory
# ---------------------------------------------------------------------------


@router.get("/scans/capabilities")
def scan_capabilities(principal: Reader) -> dict[str, list[dict[str, str]]]:
    del principal
    return {
        "targets": [
            {"kind": "git_repository", "scanner": "source"},
            {"kind": "local_path", "scanner": "source"},
            {"kind": "container_image", "scanner": "container"},
            {"kind": "binary_file", "scanner": "binary"},
            {"kind": "network_endpoint", "scanner": "network"},
            {"kind": "cloud_account", "scanner": "cloud_hsm"},
        ]
    }


@router.post("/scans", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    payload: ScanCreateRequest,
    request: Request,
    principal: Analyst,
    session: Db,
    idempotency_key: Annotated[str | None, Query(alias="idempotency_key")] = None,
) -> ScanResponse:
    project = _project(request, principal)
    # Header wins; query is accepted only for clients unable to set headers.
    idempotency_key = request.headers.get("Idempotency-Key") or idempotency_key
    if idempotency_key and len(idempotency_key) > 255:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_REQUEST", "message": "Idempotency-Key is too long."},
        )
    if (
        payload.application_id
        and application_for_project(
            session, application_id=payload.application_id, project_id=project.id
        )
        is None
    ):
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_REQUEST",
                "message": "Application is not in this project.",
            },
        )
    if idempotency_key:
        existing = session.scalar(
            select(tables.Scan).where(
                tables.Scan.requested_by == principal.user.id,
                tables.Scan.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            if existing.project_id != project.id:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "CONFLICT",
                        "message": "Idempotency key belongs to a different project.",
                    },
                )
            return _scan_with_count(session, existing)
    row = tables.Scan(
        id=str(uuid.uuid4()),
        project_id=project.id,
        target_kind=payload.target_kind.value,
        target_identifier=payload.target_identifier,
        target_reference=payload.target_reference,
        display_name=payload.display_name,
        status=ScanStatus.QUEUED.value,
        requested_by=principal.user.id,
        idempotency_key=idempotency_key,
        scanners_run=[item.value for item in payload.scanners] or None,
    )
    session.add(row)
    publish_progress(
        session,
        scan_id=row.id,
        percent=0,
        stage="queued",
        counts={"artefacts": 0},
        message="Scan is queued.",
    )
    _audit(
        session,
        request,
        principal=principal,
        project_id=project.id,
        action="scan.create",
        resource_type="scan",
        resource_id=row.id,
        details={"target_kind": row.target_kind},
    )
    session.commit()
    try:
        request.app.state.scan_dispatcher.dispatch(row.id)
    except QueueUnavailableError as error:
        row.status = ScanStatus.FAILED.value
        row.finished_at = utcnow()
        row.errors_json = [
            {
                "code": "SERVICE_UNAVAILABLE",
                "message": str(error),
                "is_retryable": True,
                "occurred_at": row.finished_at.isoformat(),
            }
        ]
        publish_progress(
            session, scan_id=row.id, percent=100, stage="failed", message=str(error)
        )
        session.commit()
        raise HTTPException(
            status_code=503, detail={"code": "SERVICE_UNAVAILABLE", "message": str(error)}
        ) from error
    return _scan_with_count(session, row)


@router.get("/scans", response_model=ScanListResponse)
def list_scans(
    request: Request,
    principal: Reader,
    session: Db,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> ScanListResponse:
    project = _project(request, principal)
    rows, total = scans_for_project(
        session, project_id=project.id, offset=offset, limit=limit
    )
    return ScanListResponse(
        items=[_scan_with_count(session, row) for row in rows],
        page=PageMeta(offset=offset, limit=limit, total=total),
    )


@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str, request: Request, principal: Reader, session: Db
) -> ScanResponse:
    project = _project(request, principal)
    row = scan_for_project(session, scan_id=scan_id, project_id=project.id)
    if row is None:
        raise _not_found("Scan")
    return _scan_with_count(session, row)


@router.post("/scans/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(
    scan_id: str, request: Request, principal: Analyst, session: Db
) -> ScanResponse:
    project = _project(request, principal)
    row = scan_for_project(session, scan_id=scan_id, project_id=project.id)
    if row is None:
        raise _not_found("Scan")
    if ScanStatus(row.status).is_terminal:
        return _scan_with_count(session, row)
    row.status = ScanStatus.CANCELLED.value
    row.finished_at = utcnow()
    publish_progress(
        session,
        scan_id=row.id,
        percent=100,
        stage="cancelled",
        message="Scan was cancelled.",
    )
    _audit(
        session,
        request,
        principal=principal,
        project_id=project.id,
        action="scan.cancel",
        resource_type="scan",
        resource_id=row.id,
    )
    session.commit()
    return _scan_with_count(session, row)


@router.post(
    "/scans/{scan_id}/rescan",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def rescan(
    scan_id: str, request: Request, principal: Analyst, session: Db
) -> ScanResponse:
    project = _project(request, principal)
    original = scan_for_project(session, scan_id=scan_id, project_id=project.id)
    if original is None:
        raise _not_found("Scan")
    replacement = tables.Scan(
        id=str(uuid.uuid4()),
        project_id=project.id,
        target_kind=original.target_kind,
        target_identifier=original.target_identifier,
        target_reference=original.target_reference,
        display_name=original.display_name,
        status=ScanStatus.QUEUED.value,
        requested_by=principal.user.id,
        scanners_run=original.scanners_run,
    )
    session.add(replacement)
    publish_progress(
        session,
        scan_id=replacement.id,
        percent=0,
        stage="queued",
        message="Re-scan is queued.",
    )
    _audit(
        session,
        request,
        principal=principal,
        project_id=project.id,
        action="scan.rescan",
        resource_type="scan",
        resource_id=replacement.id,
        details={"previous_scan_id": original.id},
    )
    session.commit()
    try:
        request.app.state.scan_dispatcher.dispatch(replacement.id)
    except QueueUnavailableError as error:
        replacement.status = ScanStatus.FAILED.value
        replacement.finished_at = utcnow()
        replacement.errors_json = [
            {"code": "SERVICE_UNAVAILABLE", "message": str(error), "is_retryable": True}
        ]
        session.commit()
        raise HTTPException(
            status_code=503, detail={"code": "SERVICE_UNAVAILABLE", "message": str(error)}
        ) from error
    return _scan_with_count(session, replacement)


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: str, request: Request, principal: Admin, session: Db) -> None:
    project = _project(request, principal)
    row = scan_for_project(session, scan_id=scan_id, project_id=project.id)
    if row is None:
        raise _not_found("Scan")
    _audit(
        session,
        request,
        principal=principal,
        project_id=project.id,
        action="scan.delete",
        resource_type="scan",
        resource_id=row.id,
    )
    session.delete(row)
    session.commit()


@router.get("/scans/{scan_id}/progress", response_model=list[ScanProgressResponse])
def scan_progress(
    scan_id: str,
    request: Request,
    principal: Reader,
    session: Db,
    after: int = Query(0, ge=0),
) -> list[ScanProgressResponse]:
    project = _project(request, principal)
    if scan_for_project(session, scan_id=scan_id, project_id=project.id) is None:
        raise _not_found("Scan")
    return [
        progress_response(row)
        for row in progress_since(session, scan_id=scan_id, after=after)
    ]


@router.get("/scans/{scan_id}/events")
async def scan_events(
    scan_id: str, request: Request, principal: Reader, after: int = Query(0, ge=0)
) -> StreamingResponse:
    project = _project(request, principal)
    with request.app.state.session_factory() as verify_session:
        if (
            scan_for_project(verify_session, scan_id=scan_id, project_id=project.id)
            is None
        ):
            raise _not_found("Scan")

    async def stream():
        sequence = after
        while True:
            with request.app.state.session_factory() as event_session:
                events = progress_since(event_session, scan_id=scan_id, after=sequence)
                for event in events:
                    sequence = event.sequence
                    payload = progress_response(event).model_dump(mode="json")
                    yield (
                        f"id: {sequence}\nevent: progress\n"
                        f"data: {json.dumps(payload)}\n\n"
                    )
            if await request.is_disconnected():
                return
            await asyncio.sleep(0.35)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/scans/{scan_id}/artefacts", response_model=ArtefactListResponse)
def scan_artefacts(
    scan_id: str,
    request: Request,
    principal: Reader,
    session: Db,
    asset_type: str | None = Query(None, alias="type"),
    priority: str | None = None,
    application_id: str | None = None,
    algorithm: str | None = None,
    quantum_status: str | None = None,
    scanner: str | None = None,
    search: str | None = Query(None, alias="q"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> ArtefactListResponse:
    project = _project(request, principal)
    scan = scan_for_project(session, scan_id=scan_id, project_id=project.id)
    if scan is None:
        raise _not_found("Scan")
    rows = _filter_artefacts(
        artefacts_for_scan(session, scan_id=scan.id),
        asset_type=asset_type,
        priority=priority,
        application_id=application_id,
        algorithm=algorithm,
        quantum_status=quantum_status,
        scanner=scanner,
        search=search,
    )
    return _artefact_query_response(
        rows, offset=offset, limit=limit, scan_status=ScanStatus(scan.status)
    )


@router.get("/artefacts", response_model=ArtefactListResponse)
def query_artefacts(
    request: Request,
    principal: Reader,
    session: Db,
    asset_type: str | None = Query(None, alias="type"),
    priority: str | None = None,
    application_id: str | None = None,
    algorithm: str | None = None,
    quantum_status: str | None = None,
    scanner: str | None = None,
    search: str | None = Query(None, alias="q"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> ArtefactListResponse:
    project = _project(request, principal)
    statement = (
        select(tables.Artefact)
        .join(tables.Scan)
        .where(tables.Scan.project_id == project.id)
        .options(
            selectinload(tables.Artefact.assessments).selectinload(
                tables.RiskAssessment.recommendation
            ),
            selectinload(tables.Artefact.review),
        )
    )
    rows = _filter_artefacts(
        list(session.scalars(statement)),
        asset_type=asset_type,
        priority=priority,
        application_id=application_id,
        algorithm=algorithm,
        quantum_status=quantum_status,
        scanner=scanner,
        search=search,
    )
    return _artefact_query_response(rows, offset=offset, limit=limit)


@router.post("/artefacts/bulk-review", response_model=BulkReviewResponse)
def bulk_review_artefacts(
    payload: BulkReviewRequest,
    request: Request,
    principal: Analyst,
    session: Db,
) -> BulkReviewResponse:
    """Persist analyst dispositions; they are never mere client-side labels."""
    project = _project(request, principal)
    rows = list(
        session.scalars(
            select(tables.Artefact)
            .join(tables.Scan)
            .where(
                tables.Scan.project_id == project.id,
                tables.Artefact.id.in_(payload.artefact_ids),
            )
        )
    )
    if len(rows) != len(payload.artefact_ids):
        raise HTTPException(
            status_code=404,
            detail={
                "code": "NOT_FOUND",
                "message": "One or more artefacts were not found in this project.",
            },
        )
    for row in rows:
        review = session.scalar(
            select(tables.ArtefactReview).where(
                tables.ArtefactReview.project_id == project.id,
                tables.ArtefactReview.artefact_id == row.id,
            )
        )
        if payload.action == "clear":
            if review is not None:
                session.delete(review)
            continue
        if review is None:
            review = tables.ArtefactReview(
                id=str(uuid.uuid4()),
                project_id=project.id,
                artefact_id=row.id,
                status=payload.action,
                owner=payload.owner,
                reason=payload.reason,
                updated_by=principal.user.id,
            )
            session.add(review)
            continue
        review.status = payload.action
        review.owner = payload.owner if payload.owner is not None else review.owner
        review.reason = payload.reason
        review.updated_by = principal.user.id
    _audit(
        session,
        request,
        principal=principal,
        project_id=project.id,
        action="artefact.bulk_review",
        resource_type="artefact_review",
        resource_id="bulk",
        details={"action": payload.action, "count": len(rows)},
    )
    session.commit()
    return BulkReviewResponse(updated=len(rows))


@router.get("/artefacts/{artefact_id}")
def get_artefact(
    artefact_id: str, request: Request, principal: Reader, session: Db
) -> dict[str, Any]:
    project = _project(request, principal)
    row = artefact_for_project(session, artefact_id=artefact_id, project_id=project.id)
    if row is None:
        raise _not_found("Artefact")
    return {
        "artefact": artefact_item(row).model_dump(mode="json"),
        "detail": row.detail_json,
        "evidence": row.evidence_json or [],
        "raw_cbom": row.raw_cbom,
        "context": context_from_row(row.context).model_dump(mode="json")
        if row.context
        else None,
        "assessments": [
            assessment_from_row(item).model_dump(mode="json") for item in row.assessments
        ],
        "recommendations": [
            recommendation_from_row(item.recommendation).model_dump(mode="json")
            for item in row.assessments
            if item.recommendation
        ],
    }


@router.get("/artefacts/{artefact_id}/risk")
def get_risk(
    artefact_id: str,
    request: Request,
    principal: Reader,
    session: Db,
) -> dict[str, Any]:
    """Return the current reproducible two-track verdict without recomputing it."""
    project = _project(request, principal)
    row = artefact_for_project(session, artefact_id=artefact_id, project_id=project.id)
    if row is None:
        raise _not_found("Artefact")
    assessment = row.latest_assessment
    if assessment is None:
        return {
            "assessment": None,
            "message": "This finding has not yet been assessed.",
        }
    return {"assessment": assessment_from_row(assessment).model_dump(mode="json")}


@router.get("/artefacts/{artefact_id}/mosca")
def get_mosca(
    artefact_id: str,
    request: Request,
    principal: Reader,
    session: Db,
) -> dict[str, Any]:
    """Expose Mosca inputs and provenance separately from the score."""
    project = _project(request, principal)
    row = artefact_for_project(session, artefact_id=artefact_id, project_id=project.id)
    if row is None:
        raise _not_found("Artefact")
    assessment = row.latest_assessment
    if assessment is None:
        return {
            "mosca": None,
            "message": "Mosca timing is unavailable until the finding is assessed.",
        }
    return {
        "mosca": assessment_from_row(assessment).mosca.model_dump(mode="json"),
        "input_provenance": dict(assessment.input_provenance_json or {}),
    }


@router.patch("/artefacts/{artefact_id}/context")
def update_context(
    artefact_id: str,
    payload: ContextPatchRequest,
    request: Request,
    principal: Analyst,
    session: Db,
) -> dict[str, Any]:
    project = _project(request, principal)
    row = artefact_for_project(session, artefact_id=artefact_id, project_id=project.id)
    if row is None:
        raise _not_found("Artefact")
    if (
        "application_id" in payload.model_fields_set
        and payload.application_id
        and application_for_project(
            session, application_id=payload.application_id, project_id=project.id
        )
        is None
    ):
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_REQUEST",
                "message": "Application is not in this project.",
            },
        )
    current = (
        context_from_row(row.context)
        if row.context
        else ArtefactContext(artefact_id=row.id)
    )
    data = current.model_dump(mode="python")
    updated_fields = payload.model_fields_set
    for field in updated_fields:
        data[field] = getattr(payload, field)
    provenance = dict(current.provenance)
    for field in updated_fields:
        provenance[field] = Provenance(
            tier=ProvenanceTier.USER, source_detail="api_context_update"
        )
    data["provenance"] = provenance
    data["updated_by"] = principal.user.id
    context = ArtefactContext.model_validate(data)
    if row.context is None:
        row.context = context_to_row(context, row_id=str(uuid.uuid4()))
    else:
        context_row = row.context
        context_row.application_id = context.application_id
        context_row.business_criticality = context.business_criticality.value
        context_row.data_classification = context.data_classification.value
        context_row.exposure = context.exposure.value
        context_row.data_category = context.data_category
        context_row.data_lifetime_years = context.data_lifetime_years
        context_row.migration_time_years = context.migration_time_years
        context_row.retention_evidence_json = [
            item.model_dump(mode="json") for item in context.retention_evidence
        ] or None
        context_row.provenance_json = {
            key: value.model_dump(mode="json")
            for key, value in context.provenance.items()
        } or None
        context_row.updated_by = principal.user.id
    profiles = load_risk_profiles()
    assessment = classify_risk(
        artefact_from_row(row),
        context,
        profiles,
        RiskSettings(),
        assessment_id=str(uuid.uuid4()),
        assessed_at=utcnow(),
    )
    append_assessment(session, assessment)
    _audit(
        session,
        request,
        principal=principal,
        project_id=project.id,
        action="artefact.context.update",
        resource_type="artefact",
        resource_id=row.id,
        details={"fields": sorted(updated_fields)},
    )
    session.commit()
    return {
        "context": context.model_dump(mode="json"),
        "assessment": assessment.model_dump(mode="json"),
    }


@router.post("/artefacts/{artefact_id}/what-if")
def what_if(
    artefact_id: str,
    payload: WhatIfRequest,
    request: Request,
    principal: Reader,
    session: Db,
) -> dict[str, Any]:
    project = _project(request, principal)
    row = artefact_for_project(session, artefact_id=artefact_id, project_id=project.id)
    if row is None:
        raise _not_found("Artefact")
    context = (
        context_from_row(row.context)
        if row.context
        else ArtefactContext(artefact_id=row.id)
    )
    if payload.x_years is not None:
        context = context.model_copy(update={"data_lifetime_years": payload.x_years})
    assessment = classify_risk(
        artefact_from_row(row),
        context,
        load_risk_profiles(),
        RiskSettings(
            planning_horizon_years=payload.z_years,
            scenario=payload.scenario or "baseline",
        ),
        assessment_id=f"what-if-{uuid.uuid4()}",
        assessed_at=datetime.now(UTC),
    )
    return {"persisted": False, "assessment": assessment.model_dump(mode="json")}


# ---------------------------------------------------------------------------
# Applications, imported context and policy settings
# ---------------------------------------------------------------------------


@router.get("/applications", response_model=list[ApplicationResponse])
def list_applications(
    request: Request, principal: Reader, session: Db
) -> list[ApplicationResponse]:
    project = _project(request, principal)
    return [
        _application_response(row)
        for row in applications_for_project(session, project_id=project.id)
    ]


@router.post(
    "/applications",
    response_model=ApplicationResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_application(
    payload: ApplicationRequest, request: Request, principal: Analyst, session: Db
) -> ApplicationResponse:
    project = _project(request, principal)
    values = payload.model_dump(mode="python")
    values.update(
        business_criticality=payload.business_criticality.value,
        data_classification=payload.data_classification.value,
        exposure=payload.exposure.value,
    )
    row = tables.Application(
        id=str(uuid.uuid4()),
        project_id=project.id,
        **values,
        provenance_json={
            field: {"tier": "user", "source_detail": "api_application_create"}
            for field in payload.model_fields_set
        },
    )
    session.add(row)
    _audit(
        session,
        request,
        principal=principal,
        project_id=project.id,
        action="application.create",
        resource_type="application",
        resource_id=row.id,
    )
    session.commit()
    return _application_response(row)


@router.put("/applications/{application_id}", response_model=ApplicationResponse)
def update_application(
    application_id: str,
    payload: ApplicationRequest,
    request: Request,
    principal: Analyst,
    session: Db,
) -> ApplicationResponse:
    project = _project(request, principal)
    row = application_for_project(
        session, application_id=application_id, project_id=project.id
    )
    if row is None:
        raise _not_found("Application")
    for field, value in payload.model_dump(mode="python").items():
        setattr(row, field, value.value if hasattr(value, "value") else value)
    provenance = dict(row.provenance_json or {})
    provenance.update(
        {
            field: {"tier": "user", "source_detail": "api_application_update"}
            for field in payload.model_fields_set
        }
    )
    row.provenance_json = provenance
    _audit(
        session,
        request,
        principal=principal,
        project_id=project.id,
        action="application.update",
        resource_type="application",
        resource_id=row.id,
    )
    session.commit()
    return _application_response(row)


@router.delete("/applications/{application_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_application(
    application_id: str, request: Request, principal: Analyst, session: Db
) -> None:
    project = _project(request, principal)
    row = application_for_project(
        session, application_id=application_id, project_id=project.id
    )
    if row is None:
        raise _not_found("Application")
    _audit(
        session,
        request,
        principal=principal,
        project_id=project.id,
        action="application.delete",
        resource_type="application",
        resource_id=row.id,
    )
    session.delete(row)
    session.commit()


@router.post("/applications/import", response_model=ImportResponse)
def import_applications(
    payload: CsvImportRequest, request: Request, principal: Analyst, session: Db
) -> ImportResponse:
    project = _project(request, principal)
    created = updated = skipped = 0
    errors: list[str] = []
    reader = csv.DictReader(io.StringIO(payload.csv_content))
    if not reader.fieldnames or "name" not in reader.fieldnames:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_REQUEST",
                "message": "CSV must include a name column.",
            },
        )
    allowed = set(ApplicationRequest.model_fields)
    for line, record in enumerate(reader, start=2):
        raw = {
            key: value.strip()
            for key, value in record.items()
            if key in allowed and value is not None and value.strip() != ""
        }
        if not raw.get("name"):
            skipped += 1
            errors.append(f"line {line}: name is required")
            continue
        for key in ("data_retention_years",):
            if key in raw:
                try:
                    raw[key] = int(raw[key])
                except ValueError:
                    errors.append(f"line {line}: {key} must be an integer")
                    raw.pop(key)
        for key in ("migration_time_years",):
            if key in raw:
                try:
                    raw[key] = float(raw[key])
                except ValueError:
                    errors.append(f"line {line}: {key} must be numeric")
                    raw.pop(key)
        if "tags" in raw:
            raw["tags"] = [
                tag.strip() for tag in str(raw["tags"]).split(";") if tag.strip()
            ]
        try:
            parsed = ApplicationRequest.model_validate(raw)
        except ValueError as error:
            skipped += 1
            errors.append(f"line {line}: {error}")
            continue
        row = session.scalar(
            select(tables.Application).where(
                tables.Application.project_id == project.id,
                tables.Application.name == parsed.name,
            )
        )
        fields = parsed.model_dump(mode="python")
        fields["business_criticality"] = parsed.business_criticality.value
        fields["data_classification"] = parsed.data_classification.value
        fields["exposure"] = parsed.exposure.value
        provenance = {
            field: {"tier": "org_preset", "source_detail": "cmdb_csv_import"}
            for field in raw
        }
        if row is None:
            row = tables.Application(
                id=str(uuid.uuid4()),
                project_id=project.id,
                **fields,
                provenance_json=provenance,
            )
            session.add(row)
            created += 1
        else:
            for field, value in fields.items():
                setattr(row, field, value)
            current_provenance = dict(row.provenance_json or {})
            current_provenance.update(provenance)
            row.provenance_json = current_provenance
            updated += 1
    _audit(
        session,
        request,
        principal=principal,
        project_id=project.id,
        action="application.import",
        resource_type="application",
        resource_id=None,
        details={"created": created, "updated": updated, "skipped": skipped},
    )
    session.commit()
    return ImportResponse(
        created=created, updated=updated, skipped=skipped, errors=errors
    )


@router.get("/settings/risk-presets", response_model=RiskPresetResponse)
def get_risk_preset(
    request: Request, principal: Reader, session: Db
) -> RiskPresetResponse:
    project = _project(request, principal)
    row = session.scalar(
        select(tables.OrgSettingVersion)
        .where(
            tables.OrgSettingVersion.project_id == project.id,
            tables.OrgSettingVersion.is_active.is_(True),
        )
        .order_by(tables.OrgSettingVersion.created_at.desc())
    )
    profiles = load_risk_profiles()
    settings = row.settings_json if row else {}
    return RiskPresetResponse(
        planning_horizon_years=settings.get("planning_horizon_years"),
        scenario=settings.get("scenario", "baseline"),
        rule_pack_toggles=settings.get("rule_pack_toggles", {}),
        version=row.version if row else "default",
        policy_version=row.policy_version
        if row and row.policy_version
        else profiles.current_security.version,
        weights_version=row.weights_version
        if row and row.weights_version
        else profiles.weights.version,
        quantum_forecast_profile_version=(
            row.quantum_forecast_profile_version
            if row and row.quantum_forecast_profile_version
            else profiles.quantum.version
        ),
        artefacts_rescored=0,
        recommendations_created=0,
    )


@router.post("/settings/risk-presets", response_model=RiskPresetResponse)
def set_risk_preset(
    payload: RiskPresetRequest, request: Request, principal: Admin, session: Db
) -> RiskPresetResponse:
    project = _project(request, principal)
    profiles = load_risk_profiles()
    version = f"api-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"
    result = apply_risk_settings_and_rescore(
        session,
        setting_id=str(uuid.uuid4()),
        setting_version=version,
        project_id=project.id,
        profiles=profiles,
        settings=RiskSettings(
            planning_horizon_years=payload.planning_horizon_years,
            scenario=payload.scenario,
        ),
        assessment_id_for=lambda _: str(uuid.uuid4()),
        assessed_at=utcnow(),
        created_by=principal.user.id,
    )
    active = session.scalar(
        select(tables.OrgSettingVersion).where(
            tables.OrgSettingVersion.version == version
        )
    )
    if active:
        active.settings_json = {
            **active.settings_json,
            "rule_pack_toggles": payload.rule_pack_toggles,
        }
    _audit(
        session,
        request,
        principal=principal,
        project_id=project.id,
        action="settings.risk_preset.update",
        resource_type="org_setting_version",
        resource_id=result.setting_version,
    )
    session.commit()
    return RiskPresetResponse(
        planning_horizon_years=payload.planning_horizon_years,
        scenario=payload.scenario,
        rule_pack_toggles=payload.rule_pack_toggles,
        version=result.setting_version,
        policy_version=profiles.current_security.version,
        weights_version=profiles.weights.version,
        quantum_forecast_profile_version=profiles.quantum.version,
        artefacts_rescored=result.artefacts_rescored,
        recommendations_created=result.recommendations_created,
    )


# ---------------------------------------------------------------------------
# Recommendations, exports and dashboard
# ---------------------------------------------------------------------------


@router.get("/recommendations")
def list_recommendations(
    request: Request, principal: Reader, session: Db
) -> list[dict[str, Any]]:
    project = _project(request, principal)
    statement = (
        select(tables.Recommendation, tables.RiskAssessment, tables.Artefact)
        .join(
            tables.RiskAssessment,
            tables.Recommendation.assessment_id == tables.RiskAssessment.id,
        )
        .join(tables.Artefact, tables.RiskAssessment.artefact_id == tables.Artefact.id)
        .join(tables.Scan, tables.Artefact.scan_id == tables.Scan.id)
        .where(tables.Scan.project_id == project.id)
    )
    return [
        {
            "artefact_id": artefact.id,
            "artefact_name": artefact.name,
            "recommendation": recommendation_from_row(rec).model_dump(mode="json"),
        }
        for rec, _, artefact in session.execute(statement)
    ]


@router.post(
    "/scans/{scan_id}/reports",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_report(
    scan_id: str,
    payload: ReportCreateRequest,
    request: Request,
    principal: Analyst,
    session: Db,
) -> ReportResponse:
    project = _project(request, principal)
    scan = scan_for_project(session, scan_id=scan_id, project_id=project.id)
    if scan is None:
        raise _not_found("Scan")
    try:
        fmt = ExportFormat(payload.format)
    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_REQUEST", "message": "Unsupported report format."},
        ) from error
    idem = request.headers.get("Idempotency-Key")
    if idem:
        existing = session.scalar(
            select(tables.Report).where(
                tables.Report.requested_by == principal.user.id,
                tables.Report.idempotency_key == idem,
            )
        )
        if existing:
            return ReportResponse(
                id=existing.id,
                scan_id=existing.scan_id,
                format=existing.format,
                size_bytes=existing.size_bytes,
                checksum_sha256=existing.checksum_sha256,
            )
    artefacts = artefacts_for_scan(session, scan_id=scan.id)
    assessments = [
        assessment_from_row(item.latest_assessment)
        for item in artefacts
        if item.latest_assessment
    ]
    recommendations = [
        recommendation_from_row(item.latest_assessment.recommendation)
        for item in artefacts
        if item.latest_assessment and item.latest_assessment.recommendation
    ]
    try:
        rendered = export(
            scan_result_from_rows(scan, artefacts), assessments, recommendations, fmt
        )
    except (ImportError, RuntimeError, ValueError) as error:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "SERVICE_UNAVAILABLE",
                "message": "Report generation is unavailable for this format.",
            },
        ) from error
    content = rendered.encode("utf-8") if isinstance(rendered, str) else rendered
    root = Path(request.app.state.report_store).resolve()
    root.mkdir(parents=True, exist_ok=True)
    report_id = str(uuid.uuid4())
    path = root / f"{report_id}.{fmt.value}"
    path.write_bytes(content)
    row = tables.Report(
        id=report_id,
        scan_id=scan.id,
        format=fmt.value,
        storage_path=str(path),
        size_bytes=len(content),
        checksum_sha256=hashlib.sha256(content).hexdigest(),
        requested_by=principal.user.id,
        idempotency_key=idem,
    )
    session.add(row)
    _audit(
        session,
        request,
        principal=principal,
        project_id=project.id,
        action="report.create",
        resource_type="report",
        resource_id=row.id,
        details={"format": fmt.value},
    )
    session.commit()
    return ReportResponse(
        id=row.id,
        scan_id=row.scan_id,
        format=row.format,
        size_bytes=row.size_bytes,
        checksum_sha256=row.checksum_sha256,
    )


@router.get("/reports/{report_id}")
def download_report(
    report_id: str, request: Request, principal: Reader, session: Db
) -> FileResponse:
    project = _project(request, principal)
    report = session.get(tables.Report, report_id)
    if report is None:
        raise _not_found("Report")
    if scan_for_project(session, scan_id=report.scan_id, project_id=project.id) is None:
        raise _not_found("Report")
    if not report.storage_path or not Path(report.storage_path).is_file():
        raise HTTPException(
            status_code=404,
            detail={"code": "NOT_FOUND", "message": "Report content is unavailable."},
        )
    return FileResponse(
        report.storage_path, filename=f"trinetra-{report.scan_id}.{report.format}"
    )


@router.get("/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(
    request: Request, principal: Reader, session: Db
) -> DashboardSummary:
    project = _project(request, principal)
    scans, scan_count = scans_for_project(
        session, project_id=project.id, offset=0, limit=10_000
    )
    rows: list[tables.Artefact] = []
    for scan in scans:
        rows.extend(artefacts_for_scan(session, scan_id=scan.id))
    priority_counts = {"p0": 0, "p1": 0, "p2": 0, "none": 0}
    needs_context = 0
    quantum_vulnerable_count = 0
    quantum_safe_count = 0
    deadlines: list[int] = []
    type_counts: dict[str, int] = {}
    application_counts: dict[str | None, int] = {}
    for row in rows:
        assessment = _latest(row)
        priority_counts[assessment.priority if assessment else "none"] += 1
        if assessment and assessment.status == AssessmentStatus.NEEDS_CONTEXT.value:
            needs_context += 1
        if row.quantum_vulnerability in {"shor_broken", "grover_weakened"}:
            quantum_vulnerable_count += 1
        if row.quantum_vulnerability == "quantum_safe":
            quantum_safe_count += 1
        if assessment and assessment.migration_deadline_year is not None:
            deadlines.append(assessment.migration_deadline_year)
        type_counts[row.type] = type_counts.get(row.type, 0) + 1
        if assessment and assessment.priority in {"p0", "p1"}:
            application_counts[row.application_id] = (
                application_counts.get(row.application_id, 0) + 1
            )
    applications = {
        application.id: application.name
        for application in session.scalars(
            select(tables.Application).where(tables.Application.project_id == project.id)
        )
    }
    top_applications = [
        DashboardApplication(
            id=application_id,
            name=applications.get(application_id, "Unassigned application"),
            at_risk_count=count,
        )
        for application_id, count in sorted(
            application_counts.items(), key=lambda item: (-item[1], item[0] or "")
        )[:10]
    ]
    trend = []
    for scan in scans[:12]:
        scan_rows = artefacts_for_scan(session, scan_id=scan.id)
        trend.append(
            DashboardTrendPoint(
                scan_id=scan.id,
                created_at=scan.created_at,
                artefact_count=len(scan_rows),
                critical_count=sum(
                    1
                    for row in scan_rows
                    if _latest(row) and _latest(row).priority == "p0"
                ),
            )
        )
    sorted_rows = _filter_artefacts(
        rows,
        asset_type=None,
        priority=None,
        application_id=None,
        algorithm=None,
        quantum_status=None,
        scanner=None,
        search=None,
    )
    return DashboardSummary(
        scan_count=scan_count,
        priority_counts=priority_counts,
        needs_context_count=needs_context,
        worst_offenders=[artefact_item(row) for row in sorted_rows[:10]],
        total_artefacts=len(rows),
        quantum_vulnerable_count=quantum_vulnerable_count,
        quantum_safe_percent=(quantum_safe_count / len(rows) * 100) if rows else None,
        nearest_mosca_deadline_year=min(deadlines) if deadlines else None,
        artefact_type_counts=type_counts,
        top_applications=top_applications,
        trend=trend,
    )


async def scan_websocket(websocket: WebSocket, scan_id: str) -> None:
    """Best-effort live stream backed by durable events (works without Redis)."""
    token = websocket.query_params.get("access_token", "")
    project_id = websocket.query_params.get("project_id", "")
    try:
        user_id = decode_access_token(token)
    except HTTPException:
        await websocket.close(code=4401)
        return
    with websocket.app.state.session_factory() as session:
        if (
            not project_id
            or project_for_user(session, project_id=project_id, user_id=user_id) is None
            or scan_for_project(session, scan_id=scan_id, project_id=project_id) is None
        ):
            await websocket.close(code=4403)
            return
    await websocket.accept()
    sequence = 0
    try:
        while True:
            with websocket.app.state.session_factory() as session:
                events = progress_since(session, scan_id=scan_id, after=sequence)
                for event in events:
                    sequence = event.sequence
                    await websocket.send_json(
                        progress_response(event).model_dump(mode="json")
                    )
            await asyncio.sleep(0.35)
    except WebSocketDisconnect:
        return


__all__ = ["router", "scan_websocket"]
