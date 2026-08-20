from __future__ import annotations

from functools import wraps
from urllib.parse import urljoin, urlparse

from flask import abort, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash

from .db import get_db
from .i18n import flash_i18n


ROLES = ("admin", "operator", "viewer")
ROLE_LABELS = {
    "admin": "Administrator",
    "operator": "Operator",
    "viewer": "Viewer",
}


def load_logged_in_user() -> None:
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
        return

    g.user = get_db().execute(
        "SELECT id, username, role, active, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    if g.user is None or not g.user["active"]:
        session.clear()
        g.user = None


def is_safe_next_url(target: str | None) -> bool:
    if not target:
        return False
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return (
        redirect_url.scheme in ("http", "https")
        and host_url.netloc == redirect_url.netloc
    )


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash_i18n("Bitte zuerst anmelden.", "error")
            return redirect(url_for("auth.login", next=request.full_path))
        return view(**kwargs)

    return wrapped_view


def roles_required(*roles: str):
    invalid = set(roles).difference(ROLES)
    if invalid:
        raise ValueError(f"Unbekannte Rollen: {', '.join(sorted(invalid))}")

    def decorator(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            if g.user is None:
                flash_i18n("Bitte zuerst anmelden.", "error")
                return redirect(url_for("auth.login", next=request.full_path))
            if g.user["role"] not in roles:
                abort(403)
            return view(**kwargs)

        return wrapped_view

    return decorator


def verify_current_password(password: str) -> bool:
    if g.user is None:
        return False
    row = get_db().execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (g.user["id"],),
    ).fetchone()
    return bool(row and check_password_hash(row["password_hash"], password))
