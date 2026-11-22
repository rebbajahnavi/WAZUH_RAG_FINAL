"""Login, logout and session check. Sessions live in an HttpOnly, SameSite=Strict cookie."""
from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from backend.config import settings
from backend.services.auth_service import AuthService, load_or_create_secret

logger = logging.getLogger("serc.auth")
router = APIRouter(prefix="/api/auth")

COOKIE_NAME = "serc_session"

auth_service = AuthService(
    settings.auth_db_file,
    load_or_create_secret(settings.secret_key, settings.session_secret_file),
    session_hours=settings.session_hours,
)


def _set_cookie(response: Response, username: str) -> None:
    response.set_cookie(
        COOKIE_NAME, auth_service.issue_token(username), max_age=auth_service.session_seconds,
        httponly=True, samesite="strict", secure=settings.cookie_secure, path="/")


def current_user_or_none(request: Request):
    return auth_service.user_from_token(request.cookies.get(COOKIE_NAME))


def require_user(request: Request) -> Dict[str, Any]:
    """FastAPI dependency: the signed-in user, or HTTP 401."""
    user = current_user_or_none(request)
    if not user:
        raise HTTPException(status_code=401, detail="Please sign in.")
    return user


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/login")
def login(req: LoginRequest, request: Request, response: Response):
    ip = request.client.host if request.client else ""
    user, error, wait = auth_service.authenticate(req.username, req.password, ip)
    if not user:
        logger.warning("Failed login for '%s' from %s", req.username[:64], ip)
        headers = {"Retry-After": str(wait)} if wait else None
        raise HTTPException(status_code=429 if wait else 401, detail=error, headers=headers)
    _set_cookie(response, user["username"])
    logger.info("User '%s' signed in", user["username"])
    return {"ok": True, "user": user}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me")
def me(user: Dict[str, Any] = Depends(require_user)):
    return user


@router.post("/password")
def change_password(req: PasswordRequest, response: Response, user: Dict[str, Any] = Depends(require_user)):
    try:
        auth_service.change_password(user["username"], req.current_password, req.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    _set_cookie(response, user["username"])  # older sessions are now invalid; keep this one signed in
    return {"ok": True}
