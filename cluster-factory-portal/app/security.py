import hashlib
import hmac
import ipaddress
import os
import secrets
from flask import abort, request, session


USER_GROUP = os.getenv("OIDC_USER_GROUP", "factory-users")
ADMIN_GROUP = os.getenv("OIDC_ADMIN_GROUP", "factory-admins")


def groups(user: dict) -> set[str]:
    return {str(group).strip("/") for group in user.get("groups", [])}


def current_user() -> dict:
    user = session.get("user")
    if not user:
        abort(401, "Authentication required")
    if USER_GROUP not in groups(user) and ADMIN_GROUP not in groups(user):
        abort(403, "Factory access has not been granted")
    return user


def is_admin(user: dict) -> bool:
    return ADMIN_GROUP in groups(user)


def require_admin() -> dict:
    user = current_user()
    if not is_admin(user):
        abort(403, "Administrator access required")
    return user


def csrf_token() -> str:
    token = session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf"] = token
    return token


def verify_csrf(supplied: str) -> None:
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(expected, supplied or ""):
        abort(403, "Invalid request token")


def owner_id(user: dict) -> str:
    return hashlib.sha256(user["sub"].encode()).hexdigest()[:20]


def client_ip() -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    candidate = forwarded or request.remote_addr or "0.0.0.0"
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return "0.0.0.0"
