import hashlib
import hmac
import ipaddress
import os
import secrets
from functools import wraps

from fastapi import HTTPException, Request


USER_GROUP = os.getenv("OIDC_USER_GROUP", "factory-users")
ADMIN_GROUP = os.getenv("OIDC_ADMIN_GROUP", "factory-admins")


def groups(user: dict) -> set[str]:
    return {str(group).strip("/") for group in user.get("groups", [])}


def current_user(request: Request) -> dict:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    if USER_GROUP not in groups(user) and ADMIN_GROUP not in groups(user):
        raise HTTPException(status_code=403, detail="Factory access has not been granted")
    return user


def is_admin(user: dict) -> bool:
    return ADMIN_GROUP in groups(user)


def require_admin(request: Request) -> dict:
    user = current_user(request)
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Administrator access required")
    return user


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def verify_csrf(request: Request, supplied: str) -> None:
    expected = request.session.get("csrf", "")
    if not expected or not hmac.compare_digest(expected, supplied or ""):
        raise HTTPException(status_code=403, detail="Invalid request token")


def owner_id(user: dict) -> str:
    return hashlib.sha256(user["sub"].encode()).hexdigest()[:20]


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    candidate = forwarded or (request.client.host if request.client else "0.0.0.0")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return "0.0.0.0"
