from __future__ import annotations

import hashlib
import hmac
from functools import wraps

from flask import Blueprint, current_app, jsonify, request

from .db import get_db
from .switching import ProfileSwitchError, switch_device_profile


bp = Blueprint("api", __name__, url_prefix="/api/v1")


def _json_error(message: str, status: int):
    return jsonify_i18n({"ok": False, "error": translate_text(message)}), status


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def api_token_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return _json_error("Bearer-Token fehlt.", 401)

        supplied = header[7:].strip()
        if not supplied:
            return _json_error("Bearer-Token fehlt.", 401)

        db = get_db()
        row = db.execute(
            "SELECT id,token_hash FROM api_tokens WHERE id=1"
        ).fetchone()
        if row is None or not hmac.compare_digest(
            row["token_hash"], _token_hash(supplied)
        ):
            return _json_error("Ungültiger API-Token.", 401)

        db.execute(
            "UPDATE api_tokens SET last_used_at=CURRENT_TIMESTAMP WHERE id=1"
        )
        db.commit()
        return view(**kwargs)

    return wrapped_view


def _addon():
    addon = current_app.extensions.get("wansinn_addon")
    if addon is None:
        raise ProfileSwitchError("Router-Add-on ist nicht geladen.")
    return addon


def _serialize_device(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "ip": row["ip"],
        "mac": row["mac"] or "",
        "note": row["note"],
        "profile": row["wan_profile"],
        "effective_profile": row["effective_profile"],
        "automation_override": row["automation_override"],
        "last_seen": row["last_seen"],
    }


@bp.get("/status")
@api_token_required
def status():
    db = get_db()
    profiles = db.execute(
        """
        SELECT profile_id,label,health_status,health_last_check,enabled
        FROM route_profiles
        ORDER BY label COLLATE NOCASE
        """
    ).fetchall()
    return jsonify({
        "ok": True,
        "version": current_app.config.get("WANSINN_VERSION", ""),
        "router": _addon().info,
        "profiles": [
            {
                "id": row["profile_id"],
                "label": row["label"],
                "enabled": bool(row["enabled"]),
                "health": row["health_status"],
                "last_check": row["health_last_check"],
            }
            for row in profiles
        ],
    })


@bp.get("/profiles")
@api_token_required
def profiles():
    rows = get_db().execute(
        "SELECT profile_id,label FROM route_profiles WHERE managed=1 AND enabled=1 "
        "ORDER BY label COLLATE NOCASE"
    ).fetchall()
    items = [{"id": "auto", "label": "AUTO"}]
    items.extend({"id": row["profile_id"], "label": row["label"]} for row in rows)
    items.append({"id": "offline", "label": "OFFLINE"})
    return jsonify({"ok": True, "profiles": items})


@bp.get("/devices")
@api_token_required
def devices():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM devices ORDER BY name COLLATE NOCASE"
    ).fetchall()

    memberships = {}
    for row in db.execute(
        """
        SELECT m.device_id,g.id,g.name
        FROM device_group_members m
        JOIN device_groups g ON g.id=m.group_id
        ORDER BY g.name COLLATE NOCASE
        """
    ).fetchall():
        memberships.setdefault(row["device_id"], []).append({
            "id": row["id"],
            "name": row["name"],
        })

    result = []
    for row in rows:
        item = _serialize_device(row)
        item["groups"] = memberships.get(row["id"], [])
        result.append(item)

    return jsonify_i18n({"ok": True, "devices": result})


@bp.get("/devices/<int:device_id>")
@api_token_required
def device(device_id):
    row = get_db().execute(
        "SELECT * FROM devices WHERE id=?",
        (device_id,),
    ).fetchone()
    if row is None:
        return _json_error("Gerät nicht gefunden.", 404)
    return jsonify_i18n({"ok": True, "device": _serialize_device(row)})


@bp.get("/groups")
@api_token_required
def groups():
    db = get_db()
    rows = db.execute(
        """
        SELECT g.id,g.name,g.note,d.id AS device_id,d.name AS device_name,d.ip
        FROM device_groups g
        LEFT JOIN device_group_members m ON m.group_id=g.id
        LEFT JOIN devices d ON d.id=m.device_id
        ORDER BY g.name COLLATE NOCASE,d.name COLLATE NOCASE
        """
    ).fetchall()

    grouped = {}
    for row in rows:
        item = grouped.setdefault(row["id"], {
            "id": row["id"],
            "name": row["name"],
            "note": row["note"],
            "devices": [],
        })
        if row["device_id"] is not None:
            item["devices"].append({
                "id": row["device_id"],
                "name": row["device_name"],
                "ip": row["ip"],
            })

    return jsonify_i18n({"ok": True, "groups": list(grouped.values())})


def _request_profile():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise ValueError("JSON-Body fehlt.")

    profile = str(payload.get("profile", "")).strip()
    valid = {"auto", "offline"} | {
        row["profile_id"]
        for row in get_db().execute(
            "SELECT profile_id FROM route_profiles WHERE managed=1 AND enabled=1"
        ).fetchall()
    }
    if profile not in valid:
        raise ValueError("Ungültiges Profil.")

    confirm_offline = payload.get("confirm_offline") is True
    if profile == "offline" and not confirm_offline:
        raise ValueError(
            "OFFLINE benötigt explizit confirm_offline=true."
        )

    return profile


def _switch(device, profile):
    return switch_device_profile(
        current_app,
        get_db(),
        device,
        profile,
        source="API",
        allow_offline=(profile == "offline"),
        allow_release_offline=True,
        verify=(profile == "offline"),
    )


@bp.post("/devices/<int:device_id>/profile")
@api_token_required
def set_device_profile(device_id):
    db = get_db()
    device = db.execute(
        "SELECT * FROM devices WHERE id=?",
        (device_id,),
    ).fetchone()
    if device is None:
        return _json_error("Gerät nicht gefunden.", 404)

    try:
        profile = _request_profile()
        applied = _switch(device, profile)
        current_app.logger.warning(
            "API: Gerät %s (%s) -> %s",
            device["name"],
            device["ip"],
            applied,
        )
        fresh = db.execute(
            "SELECT * FROM devices WHERE id=?",
            (device_id,),
        ).fetchone()
        return jsonify_i18n({
            "ok": True,
            "device": _serialize_device(fresh),
        })
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except ProfileSwitchError as exc:
        return _json_error(str(exc), 409)
    except Exception as exc:
        current_app.logger.exception("API-Geräteumschaltung fehlgeschlagen")
        return _json_error(str(exc), 500)


@bp.post("/groups/<int:group_id>/profile")
@api_token_required
def set_group_profile(group_id):
    db = get_db()
    group = db.execute(
        "SELECT id,name FROM device_groups WHERE id=?",
        (group_id,),
    ).fetchone()
    if group is None:
        return _json_error("Gruppe nicht gefunden.", 404)

    try:
        profile = _request_profile()
    except ValueError as exc:
        return _json_error(str(exc), 400)

    devices = db.execute(
        """
        SELECT d.*
        FROM devices d
        JOIN device_group_members m ON m.device_id=d.id
        WHERE m.group_id=?
        ORDER BY d.name COLLATE NOCASE
        """,
        (group_id,),
    ).fetchall()
    if not devices:
        return _json_error("Gruppe hat keine Geräte.", 409)

    results = []
    success_count = 0

    for device in devices:
        try:
            applied = _switch(device, profile)
            success_count += 1
            results.append({
                "id": device["id"],
                "name": device["name"],
                "ok": True,
                "profile": applied,
            })
        except Exception as exc:
            current_app.logger.exception(
                "API-Gruppenumschaltung fehlgeschlagen: %s (%s)",
                device["name"],
                device["ip"],
            )
            results.append({
                "id": device["id"],
                "name": device["name"],
                "ok": False,
                "error": str(exc),
            })

    current_app.logger.warning(
        "API: Gruppe %s -> %s | ok=%s failed=%s",
        group["name"],
        profile,
        success_count,
        len(devices) - success_count,
    )

    return jsonify({
        "ok": success_count == len(devices),
        "partial": 0 < success_count < len(devices),
        "group": {
            "id": group["id"],
            "name": group["name"],
        },
        "requested_profile": profile,
        "success_count": success_count,
        "failure_count": len(devices) - success_count,
        "results": results,
    }), (200 if success_count == len(devices) else 207)
