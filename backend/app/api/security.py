"""JWT authentication, password hashing and project-scoped authorization."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.models import tables
from app.models.enums import UserRole
from app.repositories import project_for_user, projects_for_user

PASSWORD_PREFIX = "scrypt-v1"
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
TOKEN_ALGORITHM = "HS256"


def _jwt_secret() -> str:
    secret = os.getenv("TRINETRA_JWT_SECRET")
    if secret:
        return secret
    # Development/test fallback. Deployments must set a stable secret or every
    # restart invalidates existing tokens, which is safer than a hard-coded one.
    return "trinetra-development-secret-change-before-production"


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P
    )
    return "$".join(
        (
            PASSWORD_PREFIX,
            base64.urlsafe_b64encode(salt).decode("ascii"),
            base64.urlsafe_b64encode(digest).decode("ascii"),
        )
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        prefix, salt_raw, digest_raw = encoded.split("$", 2)
        if prefix != PASSWORD_PREFIX:
            return False
        salt = base64.urlsafe_b64decode(salt_raw.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_raw.encode("ascii"))
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P
        )
    except (ValueError, TypeError, UnicodeError):
        return False
    return hmac.compare_digest(actual, expected)


def create_access_token(user: tables.User, *, expires_minutes: int = 480) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": user.id,
        "username": user.username,
        "iat": now,
        "exp": now + timedelta(minutes=expires_minutes),
        "typ": "access",
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=TOKEN_ALGORITHM)


def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, _jwt_secret(), algorithms=[TOKEN_ALGORITHM])
    except jwt.PyJWTError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "UNAUTHENTICATED",
                "message": "Invalid or expired access token.",
            },
        ) from error
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHENTICATED", "message": "Invalid access token."},
        )
    return subject


@dataclass(frozen=True)
class Principal:
    user: tables.User
    via_cookie: bool


def _session_from_request(request: Request) -> Session:
    return request.app.state.session_factory()


def current_principal(request: Request) -> Principal:
    authorization = request.headers.get("Authorization", "")
    via_cookie = False
    if authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
    else:
        token = request.cookies.get("trinetra_access_token", "")
        via_cookie = bool(token)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHENTICATED", "message": "Authentication is required."},
        )
    user_id = decode_access_token(token)
    with _session_from_request(request) as session:
        user = session.get(tables.User, user_id)
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "UNAUTHENTICATED", "message": "Account is unavailable."},
            )
        # Detach a small, scalar-only user so the request can safely retain it
        # after this authentication session closes.
        session.expunge(user)
    request.state.auth_via_cookie = via_cookie
    return Principal(user=user, via_cookie=via_cookie)


def require_roles(*roles: UserRole):
    def dependency(
        principal: Annotated[Principal, Depends(current_principal)],
    ) -> Principal:
        if UserRole(principal.user.role) not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "FORBIDDEN",
                    "message": "Your role cannot perform this action.",
                },
            )
        return principal

    return dependency


def require_csrf(
    request: Request, principal: Annotated[Principal, Depends(current_principal)]
) -> Principal:
    """Protect cookie-authenticated mutations; bearer tokens are not CSRFable."""
    if principal.via_cookie:
        expected = request.cookies.get("trinetra_csrf_token")
        supplied = request.headers.get("X-CSRF-Token")
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "FORBIDDEN",
                    "message": "A valid CSRF token is required.",
                },
            )
    return principal


def require_mutation(*roles: UserRole):
    """Combine role and CSRF checks so no state-changing route can omit one."""

    def dependency(
        request: Request, principal: Annotated[Principal, Depends(current_principal)]
    ) -> Principal:
        if UserRole(principal.user.role) not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "FORBIDDEN",
                    "message": "Your role cannot perform this action.",
                },
            )
        if principal.via_cookie:
            expected = request.cookies.get("trinetra_csrf_token")
            supplied = request.headers.get("X-CSRF-Token")
            if (
                not expected
                or not supplied
                or not hmac.compare_digest(expected, supplied)
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "code": "FORBIDDEN",
                        "message": "A valid CSRF token is required.",
                    },
                )
        return principal

    return dependency


def current_project(
    request: Request, principal: Annotated[Principal, Depends(current_principal)]
) -> tables.Project:
    """Resolve the selected project from header, or the sole membership."""
    requested_id = request.headers.get("X-Project-ID")
    with _session_from_request(request) as session:
        if requested_id:
            project = project_for_user(
                session, project_id=requested_id, user_id=principal.user.id
            )
        else:
            projects = projects_for_user(session, user_id=principal.user.id)
            project = projects[0] if len(projects) == 1 else None
        if project is None:
            message = (
                "Select a project with X-Project-ID."
                if not requested_id
                else "You do not have access to this project."
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "FORBIDDEN", "message": message},
            )
        session.expunge(project)
    return project


__all__ = [
    "Principal",
    "create_access_token",
    "current_principal",
    "current_project",
    "decode_access_token",
    "hash_password",
    "require_csrf",
    "require_mutation",
    "require_roles",
    "verify_password",
]
