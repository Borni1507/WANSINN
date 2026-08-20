from __future__ import annotations

import sqlite3

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .auth import ROLE_LABELS, ROLES, is_safe_next_url, login_required, roles_required
from .db import get_db
from .auth_rate_limit import client_ip, clear_success, record_failure, retry_after
from .i18n import flash_i18n, t

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/login", methods=("GET", "POST"))
def login():
    if g.user is not None:
        return redirect(url_for("main.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        source_ip = client_ip()

        blocked_for = retry_after(source_ip, username)
        if blocked_for > 0:
            current_app.logger.warning(
                "LOGIN: rate limit active for %s (%ss remaining)",
                source_ip,
                blocked_for,
            )
            flash(t("login.rate_limited", seconds=blocked_for), "error")
            response = render_template("login.html")
            return response, 429, {"Retry-After": str(blocked_for)}

        error = None
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            error = "Benutzername oder Passwort ist falsch."
        elif not user["active"]:
            error = "Dieses Benutzerkonto ist deaktiviert."

        if error is None:
            clear_success(source_ip, username)
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            next_url = request.args.get("next")
            if is_safe_next_url(next_url):
                return redirect(next_url)
            return redirect(url_for("main.index"))

        cooldown = record_failure(source_ip, username)
        if cooldown:
            current_app.logger.warning(
                "LOGIN: rate limit started for %s (%ss)",
                source_ip,
                cooldown,
            )
            flash(t("login.rate_limited", seconds=cooldown), "error")
        else:
            flash_i18n(error, "error")

    return render_template("login.html")


@bp.post("/logout")
@login_required
def logout():
    session.clear()
    flash_i18n("Du wurdest abgemeldet.", "success")
    return redirect(url_for("auth.login"))


@bp.get("/users")
@roles_required("admin")
def users():
    rows = get_db().execute(
        "SELECT id, username, role, active, created_at FROM users ORDER BY username COLLATE NOCASE"
    ).fetchall()
    return render_template(
        "users.html",
        users=rows,
        roles=ROLES,
        role_labels=ROLE_LABELS,
    )


@bp.post("/users")
@roles_required("admin")
def create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")

    if not username or len(username) < 3:
        flash_i18n("Der Benutzername muss mindestens 3 Zeichen lang sein.", "error")
        return redirect(url_for("auth.users"))
    if len(password) < 10:
        flash_i18n("Das Passwort muss mindestens 10 Zeichen lang sein.", "error")
        return redirect(url_for("auth.users"))
    if role not in ROLES:
        flash_i18n("Ungültige Rolle.", "error")
        return redirect(url_for("auth.users"))

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
        db.commit()
    except sqlite3.IntegrityError:
        flash_i18n("Dieser Benutzername existiert bereits.", "error")
    else:
        flash_i18n(f"Benutzer {username} wurde angelegt.", "success")

    return redirect(url_for("auth.users"))


@bp.post("/users/<int:user_id>/update")
@roles_required("admin")
def update_user(user_id: int):
    role = request.form.get("role", "viewer")
    active = request.form.get("active") == "on"
    new_password = request.form.get("new_password", "")

    if role not in ROLES:
        flash_i18n("Ungültige Rolle.", "error")
        return redirect(url_for("auth.users"))

    if user_id == g.user["id"] and not active:
        flash_i18n("Du kannst dein eigenes Konto nicht deaktivieren.", "error")
        return redirect(url_for("auth.users"))

    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        flash_i18n("Benutzer nicht gefunden.", "error")
        return redirect(url_for("auth.users"))

    if target["role"] == "admin" and (role != "admin" or not active):
        active_admins = db.execute(
            "SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND active = 1"
        ).fetchone()["count"]
        if active_admins <= 1:
            flash_i18n("Der letzte aktive Administrator kann nicht entfernt werden.", "error")
            return redirect(url_for("auth.users"))

    if new_password and len(new_password) < 10:
        flash_i18n("Das neue Passwort muss mindestens 10 Zeichen lang sein.", "error")
        return redirect(url_for("auth.users"))

    if new_password:
        db.execute(
            "UPDATE users SET role = ?, active = ?, password_hash = ? WHERE id = ?",
            (role, int(active), generate_password_hash(new_password), user_id),
        )
    else:
        db.execute(
            "UPDATE users SET role = ?, active = ? WHERE id = ?",
            (role, int(active), user_id),
        )
    db.commit()
    flash_i18n(f"Benutzer {target['username']} wurde aktualisiert.", "success")
    return redirect(url_for("auth.users"))
