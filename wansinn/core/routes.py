import json
import hashlib
import secrets
import re
import sqlite3
import os
import shutil
import subprocess
import zipfile
from pathlib import Path
from io import BytesIO
from datetime import datetime, timezone, timedelta

from flask import Blueprint, current_app, redirect, render_template, request, send_file, url_for, g, jsonify, session
from .i18n import (
    SUPPORTED_LANGUAGES,
    flash_i18n,
    jsonify_i18n,
    set_language,
    t,
    translate_health_text,
    translate_log_line,
)

from .auth import login_required, roles_required, verify_current_password
from .db import get_db
from .validation import validate_private_ipv4, validate_probe_ipv4, validate_mac
from .health import _probe_provider, reconcile_auto_state
from .discovery import scan_devices
from .switching import switch_device_profile, ProfileSwitchError
from .automation import execute_rule, reconcile_device_automation_now
from .plugins import load_addon
from .setup_routes import _bootstrap_mikrotik, _bootstrap_openwrt, USERNAME_RE

DEVICE_TYPES = {
    "desktop": "Desktop",
    "laptop": "Laptop",
    "server": "Server",
    "phone": "Smartphone",
    "tablet": "Tablet",
    "console": "Konsole",
    "tv": "TV / Media",
    "iot": "IoT",
    "network": "Netzwerkgerät",
    "other": "Sonstiges",
}


bp = Blueprint("main", __name__)


def addon():
    loaded = current_app.extensions.get("wansinn_addon")
    if loaded is None:
        raise RuntimeError("WANSINN ist noch nicht eingerichtet.")
    return loaded


def _normalize_color(value: str) -> str:
    value = value.strip().lower()
    if not re.fullmatch(r"#[0-9a-f]{6}", value):
        raise ValueError("Farbe muss als #RRGGBB angegeben werden.")
    return value


def _availability_key(availability: dict[str, bool]) -> str:
    return ",".join(
        f"{profile}={'1' if availability[profile] else '0'}"
        for profile in sorted(availability)
    )


def _sync_route_profile_metadata():
    """Refresh metadata for WAN profiles the admin already manages.

    Router discovery is sensor data, not WANSINN configuration.  A factory-clean
    install must therefore stay at zero WAN profiles until the administrator
    explicitly adds one.  We only refresh gateway metadata for profiles that
    already exist in WANSINN's database.
    """
    db = get_db()
    existing = {
        row["profile_id"]
        for row in db.execute("SELECT profile_id FROM route_profiles").fetchall()
    }
    if not existing:
        return

    discovered = {
        profile["id"]: profile
        for profile in addon().managed_profiles()
    }
    changed = False
    for profile_id in existing:
        profile = discovered.get(profile_id)
        if profile is None:
            continue
        db.execute(
            "UPDATE route_profiles SET gateway=? WHERE profile_id=?",
            (profile.get("gateway", ""), profile_id),
        )
        changed = True
    if changed:
        db.commit()


def _current_profile_rows():
    _sync_route_profile_metadata()
    return get_db().execute(
        "SELECT profile_id,label,color,gateway,"
        "health_target,health_interval,health_timeout,"
        "fail_threshold,recover_threshold,health_status,"
        "health_fail_count,health_ok_count,health_last_check,health_last_change,"
        "enabled,managed "
        "FROM route_profiles WHERE managed=1 "
        "ORDER BY enabled DESC,label COLLATE NOCASE"
    ).fetchall()


def _managed_profile_rows():
    _sync_route_profile_metadata()
    return get_db().execute(
        "SELECT profile_id,label,color,gateway,"
        "health_target,health_interval,health_timeout,"
        "fail_threshold,recover_threshold,health_status,"
        "health_fail_count,health_ok_count,health_last_check,health_last_change,"
        "enabled,managed "
        "FROM route_profiles WHERE managed=1 AND enabled=1 "
        "ORDER BY label COLLATE NOCASE"
    ).fetchall()



def _tail_log_file(path: Path, limit: int = 400) -> list[str]:
    """Read only the tail of the active log file, capped for responsive polling."""
    if not path.exists():
        return []

    limit = max(20, min(int(limit), 1000))
    chunk_size = 64 * 1024
    max_bytes = 512 * 1024

    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        end = fh.tell()
        data = b""
        read_total = 0
        while end > 0 and data.count(b"\n") <= limit and read_total < max_bytes:
            size = min(chunk_size, end, max_bytes - read_total)
            end -= size
            fh.seek(end)
            data = fh.read(size) + data
            read_total += size

    return data.decode("utf-8", errors="replace").splitlines()[-limit:]


@bp.get("/logs")
@roles_required("admin")
def logs_page():
    db = get_db()
    health_rows = db.execute(
        "SELECT profile_id,health_status FROM route_profiles ORDER BY profile_id"
    ).fetchall()
    health_map = {
        row["profile_id"]: row["health_status"] == "up"
        for row in health_rows
    }
    current_auto_key = _availability_key(health_map) if health_map else ""
    current_auto_state = None
    if current_auto_key:
        current_auto_state = db.execute(
            "SELECT id,name,availability_key FROM auto_states WHERE availability_key=?",
            (current_auto_key,),
        ).fetchone()

    return render_template(
        "logs.html",
        addon_info=addon().info,
        current_auto_state=current_auto_state,
        current_auto_key=current_auto_key,
    )


@bp.get("/logs/tail")
@roles_required("admin")
def logs_tail():
    try:
        limit = int(request.args.get("limit", "400"))
    except ValueError:
        limit = 400

    log_file = Path(current_app.config["WANSINN_LOG_FILE"])
    lines = [translate_log_line(line) for line in _tail_log_file(log_file, limit)]
    return jsonify({
        "ok": True,
        "lines": lines,
        "count": len(lines),
    })


@bp.get("/about")
@login_required
def about():
    return render_template("about.html")


@bp.get("/")
@login_required
def index():
    devices = get_db().execute(
        "SELECT * FROM devices ORDER BY name COLLATE NOCASE"
    ).fetchall()
    db = get_db()
    configured_rows = db.execute(
        "SELECT profile_id,label FROM route_profiles WHERE managed=1 AND enabled=1 "
        "ORDER BY label COLLATE NOCASE"
    ).fetchall()

    from .contracts import WanProfile
    profiles = [WanProfile("auto", "AUTO")]
    profiles.extend(WanProfile(row["profile_id"], row["label"]) for row in configured_rows)
    profiles.append(WanProfile("offline", "OFFLINE"))
    profile_map = {profile.id: profile for profile in profiles}
    # Counters intentionally expose two different dimensions:
    # AUTO/OFFLINE describe the control mode, while WAN counters describe
    # the route that is actually effective right now.  Otherwise all AUTO
    # devices would permanently leave dynamically configured WAN profiles at zero.
    counts = {profile.id: 0 for profile in profiles}
    for device in devices:
        mode = device["wan_profile"]
        effective = device["effective_profile"] or mode

        if mode in {"auto", "offline"}:
            counts[mode] = counts.get(mode, 0) + 1

        # Fixed/manual devices count toward their selected WAN; AUTO devices
        # count toward the currently effective WAN chosen by reconciliation.
        if effective not in {"auto", "offline"}:
            counts[effective] = counts.get(effective, 0) + 1

    counts["total"] = len(devices)
    profile_colors = {
        row["profile_id"]: row["color"]
        for row in get_db().execute(
            "SELECT profile_id,color FROM route_profiles"
        ).fetchall()
    }
    discovered = get_db().execute(
        """
        SELECT mac,ip,name,source,interface,last_seen
        FROM discovered_devices
        ORDER BY last_seen DESC,name COLLATE NOCASE,ip
        """
    ).fetchall()
    groups,group_members=_device_groups(get_db())
    return render_template(
        "index.html",
        devices=devices,
        groups=groups,
        group_members=group_members,
        profiles=profiles,
        profile_map=profile_map,
        counts=counts,
        addon_info=addon().info,
        profile_colors=profile_colors,
        discovered=discovered,
        device_types=DEVICE_TYPES,
    )



@bp.get("/devices")
@roles_required("admin")
def device_management():
    db = get_db()
    devices = db.execute(
        "SELECT * FROM devices ORDER BY name COLLATE NOCASE"
    ).fetchall()
    discovered = db.execute(
        """
        SELECT mac,ip,name,source,interface,last_seen
        FROM discovered_devices
        ORDER BY last_seen DESC,name COLLATE NOCASE,ip
        """
    ).fetchall()
    groups, group_members = _device_groups(db)
    return render_template(
        "devices.html",
        devices=devices,
        discovered=discovered,
        groups=groups,
        group_members=group_members,
        infrastructure_addresses=_infrastructure_rows(),
        management_ip=str(current_app.config.get("WANSINN_MANAGEMENT_IP", "")).strip(),
        testing_ip=str(current_app.config.get("WANSINN_TESTING_IP", "")).strip(),
        device_types=DEVICE_TYPES,
    )


def _device_groups(db):
    groups=db.execute("""
        SELECT g.id,g.name,g.note,COUNT(m.device_id) AS member_count
        FROM device_groups g
        LEFT JOIN device_group_members m ON m.group_id=g.id
        GROUP BY g.id ORDER BY g.name COLLATE NOCASE
    """).fetchall()
    members={}
    for row in db.execute("""
        SELECT m.group_id,d.id,d.name,d.ip
        FROM device_group_members m JOIN devices d ON d.id=m.device_id
        ORDER BY d.name COLLATE NOCASE
    """).fetchall():
        members.setdefault(row["group_id"],[]).append(dict(row))
    return groups,members


@bp.post("/groups")
@roles_required("admin")
def create_device_group():
    name=request.form.get("name","").strip()
    note=request.form.get("note","").strip()
    if not name:
        flash_i18n("Gruppenname fehlt.","error")
        return redirect(request.referrer or url_for("main.index"))
    db=get_db()
    try:
        cur=db.execute("INSERT INTO device_groups(name,note) VALUES(?,?)",(name,note))
        gid=cur.lastrowid
        for raw in request.form.getlist("device_ids"):
            db.execute("INSERT OR IGNORE INTO device_group_members(group_id,device_id) VALUES(?,?)",(gid,int(raw)))
        db.commit(); flash_i18n(f"Gruppe {name} angelegt.","success")
    except Exception as exc:
        db.rollback(); flash_i18n(f"Gruppe nicht angelegt: {exc}","error")
    return redirect(request.referrer or url_for("main.index"))


@bp.post("/groups/<int:group_id>")
@roles_required("admin")
def update_device_group(group_id):
    db=get_db(); name=request.form.get("name","").strip(); note=request.form.get("note","").strip()
    if not name:
        flash_i18n("Gruppenname fehlt.","error"); return redirect(request.referrer or url_for("main.index"))
    try:
        db.execute("UPDATE device_groups SET name=?,note=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(name,note,group_id))
        db.execute("DELETE FROM device_group_members WHERE group_id=?",(group_id,))
        for raw in request.form.getlist("device_ids"):
            db.execute("INSERT OR IGNORE INTO device_group_members(group_id,device_id) VALUES(?,?)",(group_id,int(raw)))
        db.commit(); flash_i18n("Gruppe gespeichert.","success")
    except Exception as exc:
        db.rollback(); flash_i18n(f"Gruppe nicht gespeichert: {exc}","error")
    return redirect(request.referrer or url_for("main.index"))


@bp.post("/groups/<int:group_id>/delete")
@roles_required("admin")
def delete_device_group(group_id):
    db=get_db()
    db.execute("DELETE FROM device_group_members WHERE group_id=?",(group_id,))
    db.execute("DELETE FROM device_groups WHERE id=?",(group_id,))
    db.commit(); flash_i18n("Gruppe gelöscht. Geräte bleiben erhalten.","success")
    return redirect(request.referrer or url_for("main.index"))


@bp.post("/groups/<int:group_id>/profile")
@roles_required("admin")
def set_group_profile(group_id):
    profile = request.form.get("profile", "").strip()
    db = get_db()

    group = db.execute(
        "SELECT id,name FROM device_groups WHERE id=?",
        (group_id,),
    ).fetchone()
    if group is None:
        flash_i18n("Gruppe nicht gefunden.", "error")
        return redirect(request.referrer or url_for("main.index"))

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
        flash_i18n("Gruppe hat keine Geräte.", "error")
        return redirect(request.referrer or url_for("main.index"))

    valid_profiles = {"auto", "offline"} | {
        row["profile_id"]
        for row in db.execute(
            "SELECT profile_id FROM route_profiles WHERE managed=1 AND enabled=1"
        ).fetchall()
    }
    if profile not in valid_profiles:
        flash_i18n("Ungültiges Gruppenprofil.", "error")
        return redirect(request.referrer or url_for("main.index"))

    # Keep the same safety boundary as the individual OFFLINE action:
    # taking a whole group offline requires the administrator password.
    if profile == "offline":
        password = request.form.get("password", "")
        if not verify_current_password(password):
            flash_i18n(
                "Gruppe nicht OFFLINE gesetzt: Administrator-Passwort ist falsch.",
                "error",
            )
            return redirect(request.referrer or url_for("main.index"))

    successes = []
    failures = []

    for device in devices:
        try:
            switch_device_profile(
                current_app,
                db,
                device,
                profile,
                source=f"GROUP/{group['name']}/{g.user['username']}",
                allow_offline=(profile == "offline"),
                allow_release_offline=True,
                verify=(profile == "offline"),
            )
            successes.append(device["name"])
        except Exception as exc:
            current_app.logger.exception(
                "Gruppenumschaltung fehlgeschlagen: %s (%s) -> %s",
                device["name"],
                device["ip"],
                profile,
            )
            failures.append(f"{device['name']}: {exc}")

    current_app.logger.warning(
        "GROUP: %s -> %s | ok=%s failed=%s",
        group["name"],
        profile,
        len(successes),
        len(failures),
    )

    if successes and not failures:
        flash_i18n(
            f"{group['name']} → {profile.upper()} "
            f"({len(successes)} Gerät(e) sofort umgeschaltet).",
            "success",
        )
    elif successes:
        flash_i18n(
            f"{group['name']}: {len(successes)} Gerät(e) umgeschaltet, "
            f"{len(failures)} fehlgeschlagen: " + " | ".join(failures[:3]),
            "error",
        )
    else:
        flash_i18n(
            f"{group['name']} konnte nicht umgeschaltet werden: "
            + " | ".join(failures[:3]),
            "error",
        )

    return redirect(request.referrer or url_for("main.index"))


@bp.post("/devices")
@roles_required("admin")
def add_device():
    name = request.form.get("name", "").strip()
    note = request.form.get("note", "").strip()
    mac_raw = request.form.get("mac", "").strip()
    try:
        ip = validate_private_ipv4(request.form.get("ip", "").strip())
        mac = validate_mac(mac_raw) if mac_raw else None
    except ValueError as exc:
        flash_i18n(str(exc), "error")
        return redirect(url_for("main.index"))

    if not name:
        flash_i18n("Gerätename fehlt.", "error")
        return redirect(url_for("main.index"))

    db = get_db()
    try:
        db.execute(
            "INSERT INTO devices(name, ip, note, mac) VALUES (?, ?, ?, ?)",
            (name[:80], ip, note[:200], mac),
        )
        db.commit()
        flash_i18n(f"{name} hinzugefügt.", "success")
    except sqlite3.IntegrityError:
        flash_i18n("IP oder MAC bereits vorhanden.", "error")
    return redirect(url_for("main.index"))


@bp.post("/devices/discover")
@roles_required("admin")
def discover_devices_now():
    try:
        stats = scan_devices(current_app)
        flash_i18n(
            f"Gerätesuche: {stats['seen']} gesehen, "
            f"{stats['new']} neu, {stats['bound']} MAC gebunden, "
            f"{stats['moved']} IP-Wechsel übernommen.",
            "success",
        )
    except Exception as exc:
        current_app.logger.exception("Manuelle Gerätesuche fehlgeschlagen")
        flash_i18n(f"Gerätesuche fehlgeschlagen: {exc}", "error")
    return redirect(url_for("main.index"))


@bp.post("/devices/discovered/<mac>/adopt")
@roles_required("admin")
def adopt_discovered_device(mac):
    try:
        mac = validate_mac(mac)
    except ValueError as exc:
        flash_i18n(str(exc), "error")
        return redirect(url_for("main.index"))

    db = get_db()
    candidate = db.execute(
        "SELECT * FROM discovered_devices WHERE mac=?",
        (mac,),
    ).fetchone()
    if candidate is None:
        flash_i18n("Gerät wurde nicht mehr in der Discovery-Liste gefunden.", "error")
        return redirect(url_for("main.index"))

    name = request.form.get("name", "").strip() or candidate["name"] or f"Gerät {candidate['ip']}"
    note = request.form.get("note", "").strip()

    try:
        db.execute(
            """
            INSERT INTO devices(name,ip,note,mac,last_seen)
            VALUES(?,?,?,?,?)
            """,
            (name[:80], candidate["ip"], note[:200], mac, candidate["last_seen"]),
        )
        db.execute("DELETE FROM discovered_devices WHERE mac=?", (mac,))
        db.commit()
        flash_i18n(f"{name} wird jetzt per MAC von WANSINN gehalten.", "success")
    except sqlite3.IntegrityError:
        db.rollback()
        flash_i18n("IP oder MAC ist bereits einem verwalteten Gerät zugeordnet.", "error")
    return redirect(url_for("main.index"))


@bp.post("/devices/discovered/<mac>/ignore")
@roles_required("admin")
def ignore_discovered_device(mac):
    try:
        mac = validate_mac(mac)
    except ValueError as exc:
        flash_i18n(str(exc), "error")
        return redirect(url_for("main.index"))
    get_db().execute("DELETE FROM discovered_devices WHERE mac=?", (mac,))
    get_db().commit()
    return redirect(url_for("main.index"))


@bp.post("/devices/<int:i>/edit")
@roles_required("admin")
def edit_device(i):
    db = get_db()
    device = db.execute("SELECT * FROM devices WHERE id=?", (i,)).fetchone()
    if device is None:
        flash_i18n("Gerät fehlt.", "error")
        return redirect(url_for("main.index"))

    name = request.form.get("name", "").strip()
    note = request.form.get("note", "").strip()
    mac_raw = request.form.get("mac", "").strip()
    device_type = request.form.get("device_type", "desktop").strip().lower()
    if device_type not in DEVICE_TYPES:
        device_type = "desktop"

    try:
        ip = validate_private_ipv4(request.form.get("ip", "").strip())
        mac = validate_mac(mac_raw) if mac_raw else None
        if not name:
            raise ValueError("Gerätename fehlt.")
    except ValueError as exc:
        flash_i18n(str(exc), "error")
        return redirect(url_for("main.index"))

    conflict = db.execute(
        "SELECT id,name FROM devices WHERE id<>? AND (ip=? OR (? IS NOT NULL AND mac=?))",
        (i, ip, mac, mac),
    ).fetchone()
    if conflict is not None:
        flash_i18n(f"IP oder MAC wird bereits von {conflict['name']} verwendet.", "error")
        return redirect(url_for("main.index"))

    old_ip = device["ip"]
    target = (
        device["effective_profile"]
        if device["wan_profile"] == "auto"
        else device["wan_profile"]
    )

    try:
        if ip != old_ip:
            # Move the active WANSINN policy, don't leave stale force-* entries.
            addon().set_device_profile(old_ip, "auto")
            addon().set_device_profile(ip, target)

        db.execute(
            """
            UPDATE devices
            SET name=?,ip=?,mac=?,note=?,device_type=?,router_imported=0,updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (name[:80], ip, mac, note[:200], device_type, i),
        )
        db.commit()
        log_msg = f"DEVICE EDIT: {device['name']} {old_ip} -> {ip}, MAC {mac or '—'}"
        current_app.logger.warning(log_msg)
        flash_i18n(f"{name} gespeichert.", "success")
    except Exception as exc:
        db.rollback()
        # Best-effort rollback of router policy if the move partially completed.
        if ip != old_ip:
            try:
                addon().set_device_profile(ip, "auto")
                addon().set_device_profile(old_ip, target)
            except Exception:
                current_app.logger.exception("Geräte-IP Rollback fehlgeschlagen")
        current_app.logger.exception("Gerät konnte nicht bearbeitet werden")
        flash_i18n(f"Gerät nicht gespeichert: {exc}", "error")

    return redirect(url_for("main.index"))


@bp.post("/devices/<int:i>/profile")
@roles_required("admin", "operator")
def set_profile(i):
    profile = request.form.get("profile", "")
    db = get_db()
    device = db.execute("SELECT * FROM devices WHERE id = ?", (i,)).fetchone()
    if not device:
        flash_i18n("Gerät fehlt.", "error")
        return redirect(url_for("main.index"))

    try:
        switch_device_profile(
            current_app,
            db,
            device,
            profile,
            source=f"MANUAL/{g.user['username']}",
            allow_offline=False,
            allow_release_offline=(g.user["role"] == "admin"),
        )
        flash_i18n(f"{device['name']} → {profile.upper()}", "success")
    except ProfileSwitchError as exc:
        flash_i18n(str(exc), "error")
    except Exception as exc:
        current_app.logger.exception("WAN-Umschaltung fehlgeschlagen")
        flash_i18n(f"Umschalten fehlgeschlagen: {exc}", "error")

    return redirect(url_for("main.index"))


@bp.post("/devices/<int:i>/offline")
@roles_required("admin")
def set_offline(i):
    password = request.form.get("password", "")
    if not verify_current_password(password):
        flash_i18n("OFFLINE nicht aktiviert: Administrator-Passwort ist falsch.", "error")
        return redirect(url_for("main.index"))

    db = get_db()
    device = db.execute("SELECT * FROM devices WHERE id = ?", (i,)).fetchone()
    if not device:
        flash_i18n("Gerät fehlt.", "error")
        return redirect(url_for("main.index"))

    try:
        switch_device_profile(
            current_app,
            db,
            device,
            "offline",
            source=f"MANUAL/{g.user['username']}",
            allow_offline=True,
            allow_release_offline=True,
            verify=True,
        )
        flash_i18n(
            f"{device['name']} ist OFFLINE. Aktive Internetverbindungen wurden beendet.",
            "success",
        )
    except ProfileSwitchError as exc:
        current_app.logger.warning("OFFLINE nicht durchgeführt: %s", exc)
        flash_i18n(f"OFFLINE fehlgeschlagen: {exc}", "error")
    except Exception as exc:
        current_app.logger.exception("OFFLINE-Aktivierung fehlgeschlagen")
        flash_i18n(f"OFFLINE fehlgeschlagen: {exc}", "error")

    return redirect(url_for("main.index"))


@bp.post("/devices/<int:i>/sync")
@roles_required("admin", "operator")
def sync(i):
    db = get_db()
    device = db.execute("SELECT * FROM devices WHERE id = ?", (i,)).fetchone()
    if not device:
        flash_i18n("Gerät fehlt.", "error")
        return redirect(url_for("main.index"))

    try:
        profile = addon().get_device_profile(device["ip"])
    except Exception as exc:
        flash_i18n(f"Sync fehlgeschlagen: {exc}", "error")
        return redirect(url_for("main.index"))

    if device["wan_profile"] == "offline" and g.user["role"] != "admin":
        if profile != "offline":
            flash_i18n(
                "Routerstatus weicht ab, aber OFFLINE darf nur ein Administrator aufheben.",
                "error",
            )
            return redirect(url_for("main.index"))
        flash_i18n("Routerstatus gelesen: Gerät bleibt OFFLINE.", "success")
        return redirect(url_for("main.index"))

    db.execute(
        "UPDATE devices SET wan_profile = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (profile, i),
    )
    db.commit()
    flash_i18n("Routerstatus übernommen.", "success")
    return redirect(url_for("main.index"))


@bp.post("/devices/<int:i>/delete")
@roles_required("admin")
def delete(i):
    db = get_db()
    device = db.execute("SELECT * FROM devices WHERE id = ?", (i,)).fetchone()
    if not device:
        flash_i18n("Gerät fehlt.", "error")
        return redirect(url_for("main.index"))

    try:
        addon().set_device_profile(device["ip"], "auto")
    except Exception as exc:
        flash_i18n(f"Löschen fehlgeschlagen: {exc}", "error")
        return redirect(url_for("main.index"))

    db.execute("DELETE FROM devices WHERE id = ?", (i,))
    db.commit()
    flash_i18n("Gerät entfernt.", "success")
    return redirect(url_for("main.index"))


def _addon_has_capability(capability):
    info = getattr(addon(), "info", None)
    return bool(info and capability in getattr(info, "capabilities", ()))



def _database_sync_check():
    from .contracts import HealthCheck

    devices = get_db().execute(
        "SELECT name, ip, wan_profile, effective_profile FROM devices ORDER BY name COLLATE NOCASE"
    ).fetchall()
    mismatches = []
    unreadable = []
    for device in devices:
        try:
            actual = addon().get_device_profile(device["ip"])
        except Exception as exc:
            unreadable.append(f"{device['name']} ({device['ip']}): {exc}")
            continue
        expected = (
            device["effective_profile"]
            if device["wan_profile"] == "auto"
            else device["wan_profile"]
        )
        if actual != expected:
            mismatches.append(
                f"{device['name']} ({device['ip']}): "
                f"DB={device['wan_profile'].upper()}, "
                f"effektiv={expected.upper()}, Router={actual.upper()}"
            )

    if unreadable:
        return HealthCheck(
            "database-sync",
            "Datenbank ↔ Router",
            "unknown",
            "Nicht alle Geräte konnten gelesen werden",
            tuple(unreadable),
        )
    if mismatches:
        return HealthCheck(
            "database-sync",
            "Datenbank ↔ Router",
            "warning",
            f"{len(mismatches)} Abweichung(en) gefunden",
            tuple(mismatches),
        )
    return HealthCheck(
        "database-sync",
        "Datenbank ↔ Router",
        "ok",
        f"{len(devices)} Gerät(e) synchron",
    )


def _check_json(check):
    return {
        "id": check.id,
        "label": translate_health_text(check.label),
        "status": check.status,
        "message": translate_health_text(check.message),
        "details": [translate_health_text(detail) for detail in check.details],
    }


def _overall_health(checks):
    statuses = {check.status for check in checks}
    if "error" in statuses:
        return "degraded", "DEGRADED"
    if "warning" in statuses or "unknown" in statuses:
        return "attention", "ATTENTION"
    return "healthy", "HEALTHY"


@bp.get("/diagnostics")
@roles_required("admin")
def diagnostics():
    """Render Medic with server-side results so diagnostics never depend on JS."""
    db = get_db()
    health_rows = db.execute(
        "SELECT profile_id,health_status FROM route_profiles ORDER BY profile_id"
    ).fetchall()
    health_map = {
        row["profile_id"]: row["health_status"] == "up"
        for row in health_rows
    }
    current_auto_key = _availability_key(health_map) if health_map else ""
    current_auto_state = None
    if current_auto_key:
        current_auto_state = db.execute(
            "SELECT id,name,availability_key FROM auto_states WHERE availability_key=?",
            (current_auto_key,),
        ).fetchone()

    checked_at = datetime.now(timezone.utc)
    checks = []

    # SSH first: if this fails, do not waste time on router-level checks.
    current_app.logger.info("MEDIC: Prüflauf gestartet")
    try:
        current_app.logger.info("MEDIC: Prüfe SSH")
        result = addon().test_connection()
        ssh_ok = bool(result.get("ok"))
        checks.append(
            HealthCheck(
                "ssh",
                "SSH-Verbindung",
                "ok" if ssh_ok else "error",
                "SSH erreichbar" if ssh_ok else "SSH nicht erreichbar",
                (),
            )
        )
    except Exception as exc:
        ssh_ok = False
        checks.append(
            HealthCheck(
                "ssh",
                "SSH-Verbindung",
                "error",
                "SSH-Prüfung fehlgeschlagen",
                (str(exc),),
            )
        )

    if ssh_ok:
        current_app.logger.info("MEDIC: SSH okay")
        try:
            current_app.logger.info("MEDIC: Starte Routerchecks")
            router_checks = addon().health_check()
            # Avoid duplicate SSH card if the add-on also emits one.
            checks.extend(check for check in router_checks if check.id != "ssh")
        except Exception as exc:
            current_app.logger.exception("Router-Diagnose fehlgeschlagen")
            checks.append(
                HealthCheck(
                    "addon",
                    "Router-Add-on",
                    "unknown",
                    "Router-Diagnose fehlgeschlagen",
                    (str(exc),),
                )
            )

        if _addon_has_capability("device-policy-routing"):
            try:
                current_app.logger.info("MEDIC: Prüfe Datenbank ↔ Router")
                db_check = _database_sync_check()
                checks.append(db_check)
            except Exception as exc:
                current_app.logger.exception("Datenbank-Sync-Diagnose fehlgeschlagen")
                checks.append(
                    HealthCheck(
                        "database-sync",
                        "Datenbank ↔ Router",
                        "unknown",
                        "Prüfung fehlgeschlagen",
                        (str(exc),),
                    )
                )
    else:
        if _addon_has_capability("device-policy-routing"):
            checks.append(
                HealthCheck(
                    "database-sync",
                    "Datenbank ↔ Router",
                    "unknown",
                    "Übersprungen · SSH nicht verfügbar",
                    (),
                )
            )

    overall_class, overall_label = _overall_health(checks)
    current_app.logger.info(
        "MEDIC: Prüflauf beendet · %s",
        ", ".join(f"{check.id}={check.status}" for check in checks),
    )
    return render_template(
        "diagnostics.html",
        addon_info=addon().info,
        current_auto_state=current_auto_state,
        current_auto_key=current_auto_key,
        medic_checks=[_check_json(check) for check in checks],
        medic_overall_class=overall_class,
        medic_overall_label=overall_label,
        medic_checked_at=checked_at.isoformat(),
    )


@bp.get("/diagnostics/checks/ssh")
@roles_required("admin")
def diagnostics_ssh_check():
    """Fast connectivity probe so Medic can report SSH independently."""
    started = datetime.now(timezone.utc)
    try:
        result = addon().test_connection()
        ok = bool(result.get("ok"))
        check = HealthCheck(
            "ssh",
            "SSH-Verbindung",
            "ok" if ok else "error",
            "SSH erreichbar" if ok else "SSH nicht erreichbar",
            (),
        )
        return jsonify({
            "ok": True,
            "check": _check_json(check),
            "checked_at": started.isoformat(),
        })
    except Exception as exc:
        check = HealthCheck(
            "ssh",
            "SSH-Verbindung",
            "error",
            "SSH-Prüfung fehlgeschlagen",
            (str(exc),),
        )
        return jsonify({
            "ok": False,
            "check": _check_json(check),
            "error": str(exc),
            "checked_at": started.isoformat(),
        }), 503


@bp.get("/diagnostics/checks/router")
@roles_required("admin")
def diagnostics_router_checks():
    """Router-side Medic phase. Does not block initial page rendering."""
    # Diagnostics must be read-only. Router policy import belongs to explicit
    # discovery/sync flows and must never delay or mutate a Medic run.
    started = datetime.now(timezone.utc)
    try:
        checks = addon().health_check()
        overall_class, overall_label = _overall_health(checks)
        return jsonify({
            "ok": True,
            "checks": [_check_json(check) for check in checks],
            "overall_class": overall_class,
            "overall_label": overall_label,
            "checked_at": started.isoformat(),
        })
    except Exception as exc:
        current_app.logger.exception("Router-Diagnose fehlgeschlagen")
        return jsonify({
            "ok": False,
            "error": str(exc),
            "checks": [],
        }), 500


@bp.get("/diagnostics/checks/database")
@roles_required("admin")
def diagnostics_database_check():
    """DB↔Router phase is only meaningful for device-policy addons."""
    if not _addon_has_capability("device-policy-routing"):
        return jsonify({
            "ok": False,
            "unsupported": True,
            "error": "Active add-on does not support device policy routing.",
        }), 409
    try:
        check = _database_sync_check()
        return jsonify_i18n({"ok": True, "check": _check_json(check)})
    except Exception as exc:
        current_app.logger.exception("Datenbank-Sync-Diagnose fehlgeschlagen")
        return jsonify({
            "ok": False,
            "check": {
                "id": "database-sync",
                "label": "Datenbank ↔ Router",
                "status": "unknown",
                "message": "Prüfung fehlgeschlagen",
                "details": [str(exc)],
            },
        }), 500


@bp.get("/diagnostics/raw")
@roles_required("admin")
def diagnostics_raw():
    """Expensive raw SSH dump; loaded only when the admin asks for it."""
    try:
        return jsonify_i18n({"ok": True, "raw": addon().diagnostics()})
    except Exception as exc:
        current_app.logger.warning("Rohdiagnose fehlgeschlagen: %s", exc)
        return jsonify_i18n({"ok": False, "error": str(exc)}), 500


@bp.get("/routes")
@roles_required("admin")
def route_config():
    try:
        profiles = list(_current_profile_rows())
        managed_profiles = [
            row for row in profiles if row["managed"] and row["enabled"]
        ]
        availability = {
            row["profile_id"]: row["health_status"] == "up"
            for row in managed_profiles
        }
    except Exception as exc:
        current_app.logger.exception("Routen konnten nicht gelesen werden")
        flash_i18n(f"Routen konnten nicht gelesen werden: {exc}", "error")
        profiles = []
        managed_profiles = []
        availability = {}

    db = get_db()
    try:
        reconcile_auto_state(current_app, db)
    except Exception:
        current_app.logger.exception(
            "AUTO-Reconcile beim Öffnen der Routenseite fehlgeschlagen"
        )

    states = db.execute(
        "SELECT id,name,availability_key FROM auto_states ORDER BY id"
    ).fetchall()
    devices = db.execute(
        "SELECT id,name,ip,wan_profile,effective_profile FROM devices "
        "ORDER BY name COLLATE NOCASE"
    ).fetchall()

    client_summary = {
        "total": db.execute("SELECT COUNT(*) AS c FROM devices").fetchone()["c"],
        "auto": db.execute(
            "SELECT COUNT(*) AS c FROM devices WHERE wan_profile='auto'"
        ).fetchone()["c"],
        "offline": db.execute(
            "SELECT COUNT(*) AS c FROM devices WHERE wan_profile='offline'"
        ).fetchone()["c"],
    }
    client_summary["fixed"] = (
        client_summary["total"] - client_summary["auto"] - client_summary["offline"]
    )

    mappings = {}
    for state in states:
        mappings[state["id"]] = {
            row["device_id"]: row["profile_id"]
            for row in db.execute(
                "SELECT device_id,profile_id "
                "FROM auto_state_device_routes WHERE state_id=?",
                (state["id"],),
            ).fetchall()
        }

    return render_template(
        "routes.html",
        profiles=profiles,
        managed_profiles=managed_profiles,
        availability=availability,
        states=states,
        devices=devices,
        mappings=mappings,
        client_summary=client_summary,
        current_key=_availability_key(availability) if availability else "",
        addon_info=addon().info,
    )


@bp.get("/routes/new")
@roles_required("admin")
def new_route_profile_page():
    return render_template("route_profile_new.html")


@bp.post("/routes")
@roles_required("admin")
def create_route_profile():
    try:
        color = _normalize_color(request.form.get("color", "#6f7d90"))
        created = addon().create_route_profile(
            request.form.get("name", "").strip(),
            request.form.get("gateway", "").strip(),
        )
        db = get_db()
        db.execute(
            "INSERT INTO route_profiles(profile_id,label,color,gateway) "
            "VALUES(?,?,?,?) "
            "ON CONFLICT(profile_id) DO UPDATE SET "
            "label=excluded.label,color=excluded.color,gateway=excluded.gateway",
            (
                created["id"],
                created["label"],
                color,
                created["gateway"],
            ),
        )
        db.commit()
        flash_i18n(f"{created['label']} angelegt.", "success")
    except Exception as exc:
        current_app.logger.exception("Routenprofil konnte nicht angelegt werden")
        flash_i18n(f"Routenprofil nicht angelegt: {exc}", "error")

    return redirect(url_for("main.route_config"))


@bp.post("/routes/<profile_id>/label")
@roles_required("admin")
def update_route_label(profile_id):
    try:
        label = request.form.get("label", "").strip()
        if not label:
            raise ValueError("Profilname darf nicht leer sein.")
        if len(label) > 64:
            raise ValueError("Profilname darf maximal 64 Zeichen lang sein.")
        if any(ord(char) < 32 for char in label):
            raise ValueError("Profilname enthält ungültige Steuerzeichen.")
        if label.casefold() in {"auto", "offline"}:
            raise ValueError("AUTO und OFFLINE sind reservierte Profilnamen.")

        db = get_db()
        exists = db.execute(
            "SELECT 1 FROM route_profiles "
            "WHERE profile_id<>? AND lower(label)=lower(?)",
            (profile_id, label),
        ).fetchone()
        if exists:
            raise ValueError("Dieser Profilname wird bereits verwendet.")

        row = db.execute(
            "SELECT profile_id FROM route_profiles WHERE profile_id=?",
            (profile_id,),
        ).fetchone()
        if row is None:
            raise ValueError("Profil nicht gefunden.")

        db.execute(
            "UPDATE route_profiles "
            "SET label=?,managed=1,enabled=1,health_status='unknown' "
            "WHERE profile_id=?",
            (label, profile_id),
        )
        db.commit()
        flash_i18n(f"Profilname gespeichert: {label}", "success")
    except Exception as exc:
        flash_i18n(f"Profilname nicht gespeichert: {exc}", "error")

    return redirect(url_for("main.route_config"))


@bp.post("/routes/<profile_id>/color")
@roles_required("admin")
def update_route_color(profile_id):
    try:
        color = _normalize_color(request.form.get("color", ""))
        db = get_db()
        db.execute(
            "UPDATE route_profiles SET color=? WHERE profile_id=?",
            (color, profile_id),
        )
        db.commit()
        flash_i18n("Profilfarbe gespeichert.", "success")
    except Exception as exc:
        flash_i18n(f"Farbe konnte nicht gespeichert werden: {exc}", "error")

    return redirect(url_for("main.route_config"))


@bp.post("/routes/<profile_id>/health")
@roles_required("admin")
def update_route_health(profile_id):
    try:
        target = validate_probe_ipv4(
            request.form.get("health_target", "").strip()
        )
        interval = int(request.form.get("health_interval", "10"))
        timeout = int(request.form.get("health_timeout", "2"))
        fail_threshold = int(request.form.get("fail_threshold", "3"))
        recover_threshold = int(request.form.get("recover_threshold", "2"))

        if not (2 <= interval <= 300):
            raise ValueError("Intervall muss zwischen 2 und 300 Sekunden liegen.")
        if not (1 <= timeout <= 10):
            raise ValueError("Timeout muss zwischen 1 und 10 Sekunden liegen.")
        if not (1 <= fail_threshold <= 10):
            raise ValueError("Fehlschläge bis DOWN müssen zwischen 1 und 10 liegen.")
        if not (1 <= recover_threshold <= 10):
            raise ValueError("Erfolge bis UP müssen zwischen 1 und 10 liegen.")

        db = get_db()
        db.execute(
            """
            UPDATE route_profiles
            SET health_target=?,
                health_interval=?,
                health_timeout=?,
                fail_threshold=?,
                recover_threshold=?,
                health_status='unknown',
                health_fail_count=0,
                health_ok_count=0,
                health_last_check='',
                health_last_change=''
            WHERE profile_id=?
            """,
            (
                target,
                interval,
                timeout,
                fail_threshold,
                recover_threshold,
                profile_id,
            ),
        )
        db.commit()
        flash_i18n(
            f"Healthcheck für {profile_id.upper()} gespeichert. "
            f"WANSINN prüft {target} über seine Testing-IP.",
            "success",
        )
    except Exception as exc:
        flash_i18n(f"Healthcheck nicht gespeichert: {exc}", "error")

    return redirect(url_for("main.route_config"))


@bp.post("/routes/<profile_id>/health/test")
@roles_required("admin")
def test_route_health(profile_id):
    row = get_db().execute(
        "SELECT health_target,health_timeout FROM route_profiles WHERE profile_id=?",
        (profile_id,),
    ).fetchone()
    if row is None:
        flash_i18n("Profil nicht gefunden.", "error")
        return redirect(url_for("main.route_config"))

    try:
        router_addon = addon()
        if "router-profile-probe" in getattr(router_addon.info, "capabilities", ()):
            ok = bool(
                router_addon.probe_profile(
                    profile_id,
                    row["health_target"],
                    row["health_timeout"],
                )
            )
        else:
            ok = _probe_provider(
                current_app,
                router_addon,
                profile_id,
                row["health_target"],
                row["health_timeout"],
            )
        flash_i18n(
            f"{profile_id.upper()} → {row['health_target']}: "
            + ("ERREICHBAR" if ok else "NICHT ERREICHBAR"),
            "success" if ok else "error",
        )
    except Exception as exc:
        flash_i18n(f"Test fehlgeschlagen: {exc}", "error")

    return redirect(url_for("main.route_config"))


def _profile_reference_counts(db, profile_id):
    direct = db.execute(
        "SELECT COUNT(*) AS c FROM devices WHERE wan_profile=?",
        (profile_id,),
    ).fetchone()["c"]
    effective = db.execute(
        "SELECT COUNT(*) AS c FROM devices WHERE effective_profile=?",
        (profile_id,),
    ).fetchone()["c"]
    auto_refs = db.execute(
        "SELECT COUNT(*) AS c FROM auto_state_device_routes WHERE profile_id=?",
        (profile_id,),
    ).fetchone()["c"]
    return {"direct": direct, "effective": effective, "auto": auto_refs}


def _migrate_profile_references(db, source, target):
    valid = {
        row["profile_id"]
        for row in db.execute(
            "SELECT profile_id FROM route_profiles WHERE enabled=1"
        ).fetchall()
    } | {"offline"}
    if target not in valid or target == source:
        raise ValueError("Ungültiges Migrationsziel.")

    direct_devices = db.execute(
        "SELECT id,name,ip FROM devices WHERE wan_profile=?",
        (source,),
    ).fetchall()

    for device in direct_devices:
        addon().set_device_profile(device["ip"], target)
        db.execute(
            """
            UPDATE devices
            SET wan_profile=?,effective_profile=?,updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (target, target, device["id"]),
        )

    # AUTO mappings are configuration references and can be replaced in bulk.
    auto_changed = db.execute(
        "UPDATE auto_state_device_routes SET profile_id=? WHERE profile_id=?",
        (target, source),
    ).rowcount

    # AUTO devices that currently happen to use source will be reconciled from
    # their scenario mapping after the migration.
    db.execute(
        """
        UPDATE devices
        SET effective_profile='auto',updated_at=CURRENT_TIMESTAMP
        WHERE wan_profile='auto' AND effective_profile=?
        """,
        (source,),
    )
    db.commit()
    reconcile_auto_state(current_app, db)
    return len(direct_devices), auto_changed


@bp.post("/routes/<profile_id>/enabled")
@roles_required("admin")
def set_route_profile_enabled(profile_id):
    db = get_db()
    row = db.execute(
        "SELECT profile_id,label,enabled FROM route_profiles WHERE profile_id=?",
        (profile_id,),
    ).fetchone()
    if row is None:
        flash_i18n("Profil nicht gefunden.", "error")
        return redirect(url_for("main.route_config"))

    enable = request.form.get("enabled") == "1"
    replacement = request.form.get("replacement", "").strip()

    try:
        if enable:
            db.execute(
                "UPDATE route_profiles "
                "SET enabled=1,managed=1,health_status='unknown' WHERE profile_id=?",
                (profile_id,),
            )
            db.commit()
            flash_i18n(f"{row['label']} aktiviert.", "success")
            return redirect(url_for("main.route_config"))

        refs = _profile_reference_counts(db, profile_id)
        total_refs = refs["direct"] + refs["effective"] + refs["auto"]

        if replacement:
            direct_changed, auto_changed = _migrate_profile_references(
                db, profile_id, replacement
            )
            db.execute(
                "UPDATE route_profiles SET enabled=0,health_status='unknown' WHERE profile_id=?",
                (profile_id,),
            )
            db.commit()
            flash_i18n(
                f"{row['label']} deaktiviert. "
                f"{direct_changed} direkte Gerät(e) und {auto_changed} AUTO-Zuordnung(en) "
                f"→ {replacement.upper()} migriert.",
                "success",
            )
        else:
            db.execute(
                "UPDATE route_profiles SET enabled=0,health_status='unknown' WHERE profile_id=?",
                (profile_id,),
            )
            db.commit()
            if total_refs:
                flash_i18n(
                    f"{row['label']} deaktiviert, wird aber noch von "
                    f"{total_refs} Referenz(en) verwendet. Migration später möglich.",
                    "error",
                )
            else:
                flash_i18n(f"{row['label']} deaktiviert.", "success")
    except Exception as exc:
        db.rollback()
        current_app.logger.exception("WAN-Profil Statusänderung fehlgeschlagen")
        flash_i18n(f"Profilstatus nicht geändert: {exc}", "error")
    return redirect(url_for("main.route_config"))


@bp.post("/routes/<profile_id>/migrate")
@roles_required("admin")
def migrate_route_profile(profile_id):
    target = request.form.get("replacement", "").strip()
    db = get_db()
    try:
        direct_changed, auto_changed = _migrate_profile_references(
            db, profile_id, target
        )
        flash_i18n(
            f"{profile_id.upper()} → {target.upper()}: "
            f"{direct_changed} direkte Gerät(e), {auto_changed} AUTO-Zuordnung(en) ersetzt.",
            "success",
        )
    except Exception as exc:
        db.rollback()
        flash_i18n(f"Migration fehlgeschlagen: {exc}", "error")
    return redirect(url_for("main.route_config"))


@bp.post("/routes/<profile_id>/delete")
@roles_required("admin")
def delete_route_profile(profile_id):
    db = get_db()
    assigned = db.execute(
        "SELECT COUNT(*) AS count FROM devices "
        "WHERE wan_profile=? OR effective_profile=?",
        (profile_id, profile_id),
    ).fetchone()["count"]
    refs = db.execute(
        "SELECT COUNT(*) AS count "
        "FROM auto_state_device_routes WHERE profile_id=?",
        (profile_id,),
    ).fetchone()["count"]

    if assigned or refs:
        flash_i18n(
            f"Profil wird noch verwendet "
            f"({assigned} Gerät(e), {refs} AUTO-Zuordnung(en)).",
            "error",
        )
        return redirect(url_for("main.route_config"))

    try:
        router_addon = addon()
        delete_hook = getattr(router_addon, "delete_route_profile", None)

        if callable(delete_hook):
            delete_hook(profile_id)

        # Router discovery is sensor data only. Removing a WAN from WANSINN
        # must remove the configuration row completely; the physical/router
        # interface may continue to exist and can be adopted again later.
        db.execute(
            "DELETE FROM route_profiles WHERE profile_id=?",
            (profile_id,),
        )
        flash_i18n(
            f"{profile_id.upper()} aus WANSINN-Verwaltung entfernt.",
            "success",
        )

        db.commit()
    except Exception as exc:
        db.rollback()
        current_app.logger.exception("Routenprofil konnte nicht gelöscht werden")
        flash_i18n(f"Profil nicht gelöscht: {exc}", "error")

    return redirect(url_for("main.route_config"))


@bp.post("/routes/auto-states")
@roles_required("admin")
def create_auto_state():
    return _save_auto_state(None)


@bp.post("/routes/auto-states/<int:state_id>")
@roles_required("admin")
def update_auto_state(state_id):
    return _save_auto_state(state_id)


def _save_auto_state(state_id):
    name = request.form.get("name", "").strip() or "AUTO-Zustand"
    profiles = [
        row["profile_id"]
        for row in _managed_profile_rows()
    ]
    availability = {
        profile: request.form.get(f"available_{profile}") == "on"
        for profile in profiles
    }
    key = _availability_key(availability)

    db = get_db()

    # A single availability combination may only map to one state.
    duplicate = db.execute(
        """
        SELECT id,name FROM auto_states
        WHERE availability_key=?
        AND (? IS NULL OR id<>?)
        """,
        (key, state_id, state_id),
    ).fetchone()
    if duplicate is not None:
        flash_i18n(
            f"Diese WAN-Kombination wird bereits von „{duplicate['name']}“ verwendet.",
            "error",
        )
        return redirect(url_for("main.route_config"))

    if state_id is None:
        cursor = db.execute(
            "INSERT INTO auto_states(name,availability_key) VALUES(?,?)",
            (name[:80], key),
        )
        state_id = cursor.lastrowid
    else:
        existing = db.execute(
            "SELECT id FROM auto_states WHERE id=?",
            (state_id,),
        ).fetchone()
        if existing is None:
            flash_i18n("AUTO-Zustand nicht gefunden.", "error")
            return redirect(url_for("main.route_config"))

        db.execute(
            "UPDATE auto_states SET name=?,availability_key=? WHERE id=?",
            (name[:80], key, state_id),
        )
        db.execute(
            "DELETE FROM auto_state_device_routes WHERE state_id=?",
            (state_id,),
        )

    valid_profiles = set(profiles) | {"offline"}
    devices = db.execute(
        "SELECT id FROM devices ORDER BY id"
    ).fetchall()

    for device in devices:
        selected = request.form.get(f"device_{device['id']}", "")
        if selected in valid_profiles:
            db.execute(
                """
                INSERT INTO auto_state_device_routes
                (state_id,device_id,profile_id)
                VALUES(?,?,?)
                """,
                (state_id, device["id"], selected),
            )

    db.commit()

    current_health = {
        row["profile_id"]: row["health_status"] == "up"
        for row in db.execute(
            "SELECT profile_id,health_status FROM route_profiles"
        ).fetchall()
    }
    current_key = _availability_key(current_health) if current_health else ""

    if current_key == key:
        reconcile_auto_state(current_app, db)
        flash_i18n(
            f"AUTO-Zustand „{name}“ gespeichert und sofort angewendet.",
            "success",
        )
    else:
        flash_i18n(f"AUTO-Zustand „{name}“ gespeichert.", "success")

    return redirect(url_for("main.route_config"))


@bp.post("/routes/auto-states/save-all")
@roles_required("admin")
def save_all_auto_states():
    """Save every AUTO scenario in one transaction."""
    db = get_db()
    profiles = [row["profile_id"] for row in _current_profile_rows()]
    valid_profiles = set(profiles) | {"offline"}
    states = db.execute(
        "SELECT id,name,availability_key FROM auto_states ORDER BY id"
    ).fetchall()
    devices = db.execute(
        "SELECT id FROM devices ORDER BY id"
    ).fetchall()

    prepared = []
    keys = {}

    for state in states:
        sid = state["id"]
        name = request.form.get(f"state_{sid}_name", "").strip() or "AUTO-Zustand"
        availability = {
            profile: request.form.get(f"state_{sid}_available_{profile}") == "on"
            for profile in profiles
        }
        key = _availability_key(availability)

        if key in keys:
            flash_i18n(
                f"Nicht gespeichert: „{name}“ und „{keys[key]}“ verwenden "
                "dieselbe WAN-Kombination.",
                "error",
            )
            return redirect(url_for("main.route_config"))
        keys[key] = name

        assignments = {}
        for device in devices:
            selected = request.form.get(
                f"state_{sid}_device_{device['id']}", ""
            ).strip()
            if selected and selected not in valid_profiles:
                flash_i18n(
                    f"Nicht gespeichert: ungültiges Ziel in „{name}“.",
                    "error",
                )
                return redirect(url_for("main.route_config"))
            if selected:
                assignments[device["id"]] = selected

        prepared.append((sid, name[:80], key, assignments))

    try:
        for sid, name, key, assignments in prepared:
            db.execute(
                "UPDATE auto_states SET name=?,availability_key=? WHERE id=?",
                (name, key, sid),
            )
            db.execute(
                "DELETE FROM auto_state_device_routes WHERE state_id=?",
                (sid,),
            )
            for device_id, profile_id in assignments.items():
                db.execute(
                    """
                    INSERT INTO auto_state_device_routes
                    (state_id,device_id,profile_id)
                    VALUES(?,?,?)
                    """,
                    (sid, device_id, profile_id),
                )
        db.commit()

        # Reconcile once, after the complete matrix is consistent.
        reconcile_auto_state(current_app, db)
        current_app.logger.warning(
            "CONFIG: alle %s AUTO-Zustände gemeinsam gespeichert",
            len(prepared),
        )
        flash_i18n(
            f"Alle {len(prepared)} AUTO-Zustände gespeichert.",
            "success",
        )
    except Exception as exc:
        db.rollback()
        current_app.logger.exception("AUTO-Zustände konnten nicht gemeinsam gespeichert werden")
        flash_i18n(f"AUTO-Zustände nicht gespeichert: {exc}", "error")

    return redirect(url_for("main.route_config"))


@bp.post("/routes/auto-states/<int:state_id>/replace")
@roles_required("admin")
def replace_auto_state_profile(state_id):
    source = request.form.get("source", "").strip()
    target = request.form.get("target", "").strip()
    db = get_db()
    state = db.execute("SELECT id,name FROM auto_states WHERE id=?", (state_id,)).fetchone()
    if state is None:
        flash_i18n("AUTO-Zustand nicht gefunden.", "error")
        return redirect(url_for("main.route_config"))

    valid = {
        row["profile_id"]
        for row in db.execute(
            "SELECT profile_id FROM route_profiles WHERE enabled=1"
        ).fetchall()
    } | {"offline"}

    if target not in valid or not source or source == target:
        flash_i18n("Ungültige Ersetzung.", "error")
        return redirect(url_for("main.route_config"))

    changed = db.execute(
        """
        UPDATE auto_state_device_routes
        SET profile_id=?
        WHERE state_id=? AND profile_id=?
        """,
        (target, state_id, source),
    ).rowcount
    db.commit()
    flash_i18n(
        f"„{state['name']}“: {changed}× {source.upper()} → {target.upper()} ersetzt.",
        "success",
    )
    return redirect(url_for("main.route_config"))


@bp.post("/routes/auto-states/<int:state_id>/duplicate")
@roles_required("admin")
def duplicate_auto_state(state_id):
    db = get_db()
    state = db.execute(
        "SELECT id,name,availability_key FROM auto_states WHERE id=?",
        (state_id,),
    ).fetchone()
    if state is None:
        flash_i18n("AUTO-Zustand nicht gefunden.", "error")
        return redirect(url_for("main.route_config"))

    # A duplicate needs a unique availability signature. We therefore clone
    # only name + device mappings into a draft-like new state with all WANs
    # unchecked. The admin then edits it in one pass.
    profiles = [
        row["profile_id"]
        for row in _managed_profile_rows()
    ]
    empty_key = _availability_key({profile: False for profile in profiles})

    duplicate = db.execute(
        "SELECT id FROM auto_states WHERE availability_key=?",
        (empty_key,),
    ).fetchone()
    if duplicate is not None:
        flash_i18n(
            "Ein Zustand mit komplett deaktivierten WANs existiert bereits. "
            "Bitte diesen zuerst bearbeiten.",
            "error",
        )
        return redirect(url_for("main.route_config"))

    cursor = db.execute(
        "INSERT INTO auto_states(name,availability_key) VALUES(?,?)",
        (f"{state['name']} Kopie"[:80], empty_key),
    )
    new_id = cursor.lastrowid

    mappings = db.execute(
        """
        SELECT device_id,profile_id
        FROM auto_state_device_routes
        WHERE state_id=?
        """,
        (state_id,),
    ).fetchall()

    for row in mappings:
        db.execute(
            """
            INSERT INTO auto_state_device_routes
            (state_id,device_id,profile_id)
            VALUES(?,?,?)
            """,
            (new_id, row["device_id"], row["profile_id"]),
        )

    db.commit()
    flash_i18n("AUTO-Zustand dupliziert. WAN-Kombination jetzt anpassen.", "success")
    return redirect(url_for("main.route_config"))


@bp.post("/routes/auto-states/<int:state_id>/delete")
@roles_required("admin")
def delete_auto_state(state_id):
    db = get_db()
    db.execute("DELETE FROM auto_states WHERE id=?", (state_id,))
    db.commit()
    flash_i18n("AUTO-Zustand gelöscht.", "success")
    return redirect(url_for("main.route_config"))


@bp.post("/routes/auto/apply")
@roles_required("admin")
def apply_auto_state():
    try:
        rows = get_db().execute(
            "SELECT profile_id,health_status FROM route_profiles"
        ).fetchall()
        availability = {
            row["profile_id"]: row["health_status"] == "up"
            for row in rows
        }
        key = _availability_key(availability)

        db = get_db()
        state = db.execute(
            "SELECT id,name FROM auto_states WHERE availability_key=?",
            (key,),
        ).fetchone()
        if state is None:
            raise RuntimeError(
                f"Kein AUTO-Zustand für {key} konfiguriert."
            )

        mapping = {
            row["device_id"]: row["profile_id"]
            for row in db.execute(
                "SELECT device_id,profile_id "
                "FROM auto_state_device_routes WHERE state_id=?",
                (state["id"],),
            ).fetchall()
        }

        applied = 0
        skipped = 0
        for device in db.execute(
            "SELECT id,name,ip FROM devices WHERE wan_profile='auto'"
        ).fetchall():
            target = mapping.get(device["id"])
            if not target:
                skipped += 1
                continue

            if target != "offline" and not availability.get(target, False):
                raise RuntimeError(
                    f"{device['name']} soll {target.upper()} nutzen, "
                    "aber dieses WAN ist aktuell nicht verfügbar."
                )

            addon().apply_effective_profile(device["ip"], target)
            db.execute(
                "UPDATE devices SET effective_profile=?, "
                "updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (target, device["id"]),
            )
            applied += 1

        db.commit()
        flash_i18n(
            f"AUTO-Zustand „{state['name']}“ angewendet: "
            f"{applied} Gerät(e), {skipped} ohne Zuordnung.",
            "success",
        )
    except Exception as exc:
        current_app.logger.exception(
            "AUTO-Zustand konnte nicht angewendet werden"
        )
        flash_i18n(f"AUTO konnte nicht angewendet werden: {exc}", "error")

    return redirect(url_for("main.route_config"))


def _infrastructure_rows():
    return get_db().execute(
        """
        SELECT id,ip,name,note
        FROM infrastructure_addresses
        ORDER BY name COLLATE NOCASE, ip
        """
    ).fetchall()


def _automation_next_text(rule, now=None):
    now = now or datetime.now()
    days = {int(x) for x in rule["weekdays"].split(",") if x}
    hour, minute = (int(x) for x in rule["time_hhmm"].split(":"))
    names = ("Mo","Di","Mi","Do","Fr","Sa","So")
    for offset in range(8):
        candidate = (now + timedelta(days=offset)).replace(
            hour=hour,minute=minute,second=0,microsecond=0
        )
        if candidate.weekday() not in days or candidate <= now:
            continue
        if offset == 0: return f"Heute {candidate:%H:%M}"
        if offset == 1: return f"Morgen {candidate:%H:%M}"
        return f"{names[candidate.weekday()]} {candidate:%H:%M}"
    return "—"

def _automation_days_from_form():
    days = [
        str(day)
        for day in range(7)
        if request.form.get(f"day_{day}") == "on"
    ]
    if not days:
        raise ValueError("Mindestens einen Wochentag auswählen.")
    return days


def _shift_weekdays(days, offset):
    return ",".join(
        str((int(day) + offset) % 7)
        for day in days
    )


def _sync_automation_window_rules(db, window_id):
    window = db.execute(
        """
        SELECT id,device_id,mode,start_hhmm,end_hhmm,weekdays,active
        FROM automation_windows WHERE id=?
        """,
        (window_id,),
    ).fetchone()
    if window is None:
        raise ValueError("Zeitfenster nicht gefunden.")

    days = [x for x in window["weekdays"].split(",") if x]
    overnight = window["end_hhmm"] <= window["start_hhmm"]

    if window["mode"] == "online":
        start_action, end_action = "online", "offline"
    else:
        start_action, end_action = "offline", "online"

    start_days = ",".join(days)
    end_days = _shift_weekdays(days, 1) if overnight else start_days

    desired = {
        "start": (start_action, window["start_hhmm"], start_days),
        "end": (end_action, window["end_hhmm"], end_days),
    }

    for edge, (action, hhmm, weekdays) in desired.items():
        existing = db.execute(
            """
            SELECT id FROM automation_rules
            WHERE window_id=? AND window_edge=?
            """,
            (window_id, edge),
        ).fetchone()
        if existing:
            db.execute(
                """
                UPDATE automation_rules
                SET device_id=?,action=?,time_hhmm=?,weekdays=?,active=?,
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (
                    window["device_id"], action, hhmm, weekdays,
                    window["active"], existing["id"],
                ),
            )
        else:
            db.execute(
                """
                INSERT INTO automation_rules(
                    device_id,action,time_hhmm,weekdays,active,window_id,window_edge
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    window["device_id"], action, hhmm, weekdays,
                    window["active"], window_id, edge,
                ),
            )


def _automation_window_values(allow_missing_device=False):
    try:
        device_id = int(request.form.get("device_id", "0") or 0)
    except ValueError:
        raise ValueError("Ungültiges Gerät.")

    mode = request.form.get("mode", "").strip()
    start_hhmm = request.form.get("start_hhmm", "").strip()
    end_hhmm = request.form.get("end_hhmm", "").strip()
    active = int(request.form.get("active", "on") == "on")
    weekdays = _automation_days_from_form()

    if mode not in {"online", "offline"}:
        raise ValueError("Ungültiger Fenstertyp.")
    for value in (start_hhmm, end_hhmm):
        if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value):
            raise ValueError("Ungültige Uhrzeit.")
    if start_hhmm == end_hhmm:
        raise ValueError("Start und Ende dürfen nicht identisch sein.")
    if not allow_missing_device and get_db().execute(
        "SELECT id FROM devices WHERE id=?", (device_id,)
    ).fetchone() is None:
        raise ValueError("Gerät nicht gefunden.")

    return device_id, mode, start_hhmm, end_hhmm, ",".join(weekdays), active


@bp.get("/automation")
@roles_required("admin")
def automation_page():
    db=get_db()
    devices=db.execute(
        "SELECT id,name,ip,wan_profile,effective_profile,automation_override,"
        "automation_override_at FROM devices ORDER BY name COLLATE NOCASE,ip"
    ).fetchall()

    # Standalone points are the advanced mode. Generated window edges are hidden there.
    rules=db.execute(
        "SELECT r.id,r.device_id,r.action,r.time_hhmm,r.weekdays,r.active,"
        "d.name AS device_name,d.ip AS device_ip FROM automation_rules r "
        "JOIN devices d ON d.id=r.device_id "
        "WHERE r.window_id IS NULL "
        "ORDER BY d.name COLLATE NOCASE,r.time_hhmm,r.id"
    ).fetchall()

    windows=db.execute(
        """
        SELECT w.id,w.device_id,w.mode,w.start_hhmm,w.end_hhmm,w.weekdays,w.active,
               d.name AS device_name,d.ip AS device_ip,
               d.wan_profile,d.effective_profile,d.automation_override
        FROM automation_windows w
        JOIN devices d ON d.id=w.device_id
        ORDER BY d.name COLLATE NOCASE,w.start_hhmm,w.id
        """
    ).fetchall()

    next_times={x["id"]:_automation_next_text(x) for x in rules}

    timeline_by_device={}
    for device in devices:
        timeline_by_device[device["id"]]={
            "id":device["id"],
            "name":device["name"],
            "ip":device["ip"],
            "wan_profile":device["wan_profile"],
            "effective_profile":device["effective_profile"],
            "override":device["automation_override"],
            "windows":[],
            "points":[],
        }

    for window in windows:
        timeline_by_device[window["device_id"]]["windows"].append({
            "id":window["id"],
            "mode":window["mode"],
            "start":window["start_hhmm"],
            "end":window["end_hhmm"],
            "weekdays":[int(x) for x in window["weekdays"].split(",") if x],
            "active":bool(window["active"]),
        })

    for rule in rules:
        timeline_by_device[rule["device_id"]]["points"].append({
            "id":rule["id"],
            "action":rule["action"],
            "time":rule["time_hhmm"],
            "weekdays":[int(x) for x in rule["weekdays"].split(",") if x],
            "active":bool(rule["active"]),
            "next":next_times.get(rule["id"],"—"),
        })

    timeline_devices=[
        value for value in timeline_by_device.values()
        if value["windows"] or value["points"]
    ]

    groups,group_members=_device_groups(db)
    return render_template(
        "automation.html",
        devices=devices,
        groups=groups,
        group_members=group_members,
        rules=rules,
        windows=windows,
        next_times=next_times,
        timeline_devices=timeline_devices,
    )


def _automation_form_values():
    try:
        device_id=int(request.form.get("device_id","0"))
    except ValueError:
        raise ValueError("Ungültiges Gerät.")
    action=request.form.get("action","").strip()
    time_hhmm=request.form.get("time_hhmm","").strip()
    active=int(request.form.get("active")=="on")
    if action not in {"offline","online"}:
        raise ValueError("Ungültige Aktion.")
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d",time_hhmm):
        raise ValueError("Ungültige Uhrzeit.")
    weekdays=[str(i) for i in range(7) if request.form.get(f"day_{i}")=="on"]
    if not weekdays:
        raise ValueError("Mindestens einen Wochentag auswählen.")
    if get_db().execute("SELECT id FROM devices WHERE id=?",(device_id,)).fetchone() is None:
        raise ValueError("Gerät nicht gefunden.")
    return device_id,action,time_hhmm,",".join(weekdays),active

@bp.post("/automation/windows")
@roles_required("admin")
def create_automation_window():
    try:
        group_id=request.form.get("group_id","").strip()
        values = _automation_window_values(allow_missing_device=bool(group_id))
        db = get_db()
        if group_id:
            member_ids=[row["device_id"] for row in db.execute(
                "SELECT device_id FROM device_group_members WHERE group_id=?",(int(group_id),)
            ).fetchall()]
            if not member_ids:
                raise ValueError("Gruppe hat keine Geräte.")
            for member_id in member_ids:
                group_values=(member_id,*values[1:])
                cur=db.execute(
                    "INSERT INTO automation_windows(device_id,mode,start_hhmm,end_hhmm,weekdays,active) VALUES(?,?,?,?,?,?)",
                    group_values,
                )
                _sync_automation_window_rules(db,cur.lastrowid)
            db.commit()
            for member_id in member_ids:
                reconcile_device_automation_now(current_app,db,member_id)
            flash_i18n(f"Zeitfenster für {len(member_ids)} Gruppen-Gerät(e) angelegt.","success")
            return redirect(url_for("main.automation_page"))
        cur = db.execute(
            """
            INSERT INTO automation_windows(
                device_id,mode,start_hhmm,end_hhmm,weekdays,active
            ) VALUES(?,?,?,?,?,?)
            """,
            values,
        )
        _sync_automation_window_rules(db, cur.lastrowid)
        db.commit()
        reconcile_device_automation_now(current_app, db, values[0])
        flash_i18n("Zeitfenster angelegt und aktueller Zustand geprüft.", "success")
    except Exception as exc:
        get_db().rollback()
        flash_i18n(f"Zeitfenster nicht angelegt: {exc}", "error")
    return redirect(url_for("main.automation_page"))


@bp.post("/automation/windows/<int:window_id>")
@roles_required("admin")
def update_automation_window(window_id):
    try:
        values = _automation_window_values()
        db = get_db()
        existing_window = db.execute(
            "SELECT id,device_id FROM automation_windows WHERE id=?",
            (window_id,),
        ).fetchone()
        if existing_window is None:
            raise ValueError("Zeitfenster nicht gefunden.")
        old_device_id = existing_window["device_id"]
        db.execute(
            """
            UPDATE automation_windows
            SET device_id=?,mode=?,start_hhmm=?,end_hhmm=?,weekdays=?,active=?,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (*values, window_id),
        )
        _sync_automation_window_rules(db, window_id)
        db.commit()
        reconcile_device_automation_now(current_app, db, old_device_id)
        if values[0] != old_device_id:
            reconcile_device_automation_now(current_app, db, values[0])
        flash_i18n("Zeitfenster gespeichert und aktueller Zustand geprüft.", "success")
    except Exception as exc:
        get_db().rollback()
        flash_i18n(f"Zeitfenster nicht gespeichert: {exc}", "error")
    return redirect(url_for("main.automation_page"))


@bp.post("/automation/windows/<int:window_id>/delete")
@roles_required("admin")
def delete_automation_window(window_id):
    db = get_db()
    try:
        window = db.execute(
            "SELECT device_id FROM automation_windows WHERE id=?",
            (window_id,),
        ).fetchone()
        affected_device_id = window["device_id"] if window else None
        db.execute("DELETE FROM automation_rules WHERE window_id=?", (window_id,))
        db.execute("DELETE FROM automation_windows WHERE id=?", (window_id,))
        db.commit()
        if affected_device_id is not None:
            reconcile_device_automation_now(
                current_app, db, affected_device_id
            )
        flash_i18n("Zeitfenster gelöscht und aktueller Zustand geprüft.", "success")
    except Exception as exc:
        db.rollback()
        flash_i18n(f"Zeitfenster nicht gelöscht: {exc}", "error")
    return redirect(url_for("main.automation_page"))


@bp.post("/automation/windows/<int:window_id>/timing")
@roles_required("admin")
def update_automation_window_timing(window_id):
    start_hhmm = request.form.get("start_hhmm", "").strip()
    end_hhmm = request.form.get("end_hhmm", "").strip()
    for value in (start_hhmm, end_hhmm):
        if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value):
            return jsonify_i18n({"ok":False,"error":"Ungültige Uhrzeit."}),400
    if start_hhmm == end_hhmm:
        return jsonify_i18n({"ok":False,"error":"Start und Ende dürfen nicht identisch sein."}),400

    db = get_db()
    window = db.execute(
        "SELECT id,device_id FROM automation_windows WHERE id=?",
        (window_id,),
    ).fetchone()
    if window is None:
        return jsonify_i18n({"ok":False,"error":"Zeitfenster nicht gefunden."}),404
    try:
        db.execute(
            """
            UPDATE automation_windows
            SET start_hhmm=?,end_hhmm=?,updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (start_hhmm,end_hhmm,window_id),
        )
        _sync_automation_window_rules(db,window_id)
        db.commit()
        applied = reconcile_device_automation_now(
            current_app, db, window["device_id"]
        )
        current_app.logger.warning(
            "SCHEDULE: Zeitfenster %s auf %s-%s verschoben; jetzt=%s",
            window_id,start_hhmm,end_hhmm,applied or "unverändert",
        )
        return jsonify({
            "ok":True,
            "start_hhmm":start_hhmm,
            "end_hhmm":end_hhmm,
            "applied_now":applied,
        })
    except Exception as exc:
        db.rollback()
        current_app.logger.exception("Zeitfenster konnte nicht verschoben werden")
        return jsonify_i18n({"ok":False,"error":str(exc)}),500


@bp.post("/automation")
@roles_required("admin")
def create_automation_rule():
    try:
        values=_automation_form_values()
        db=get_db()
        db.execute(
            "INSERT INTO automation_rules(device_id,action,time_hhmm,weekdays,active) "
            "VALUES(?,?,?,?,?)",values
        )
        db.commit()
        reconcile_device_automation_now(current_app, db, values[0])
        flash_i18n("Automation angelegt und aktueller Zustand geprüft.","success")
    except Exception as exc:
        flash_i18n(f"Automation nicht angelegt: {exc}","error")
    return redirect(url_for("main.automation_page"))

@bp.post("/automation/<int:rule_id>")
@roles_required("admin")
def update_automation_rule(rule_id):
    try:
        values=_automation_form_values()
        db=get_db()
        old_rule = db.execute(
            "SELECT id,device_id FROM automation_rules WHERE id=?",
            (rule_id,),
        ).fetchone()
        if old_rule is None:
            raise ValueError("Automation nicht gefunden.")
        old_device_id = old_rule["device_id"]
        db.execute(
            "UPDATE automation_rules SET device_id=?,action=?,time_hhmm=?,weekdays=?,"
            "active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (*values,rule_id)
        )
        db.commit()
        reconcile_device_automation_now(current_app, db, old_device_id)
        if values[0] != old_device_id:
            reconcile_device_automation_now(current_app, db, values[0])
        flash_i18n("Automation gespeichert und aktueller Zustand geprüft.","success")
    except Exception as exc:
        flash_i18n(f"Automation nicht gespeichert: {exc}","error")
    return redirect(url_for("main.automation_page"))

@bp.post("/automation/<int:rule_id>/time")
@roles_required("admin")
def update_automation_rule_time(rule_id):
    time_hhmm = request.form.get("time_hhmm", "").strip()
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", time_hhmm):
        return jsonify_i18n({"ok": False, "error": "Ungültige Uhrzeit."}), 400

    db = get_db()
    rule = db.execute(
        "SELECT id,device_id FROM automation_rules WHERE id=?",
        (rule_id,),
    ).fetchone()
    if rule is None:
        return jsonify_i18n({"ok": False, "error": "Automation nicht gefunden."}), 404

    db.execute(
        """
        UPDATE automation_rules
        SET time_hhmm=?,updated_at=CURRENT_TIMESTAMP
        WHERE id=?
        """,
        (time_hhmm, rule_id),
    )
    db.commit()
    applied = reconcile_device_automation_now(
        current_app, db, rule["device_id"]
    )
    current_app.logger.warning(
        "SCHEDULE: Regel %s per Timeline auf %s verschoben; jetzt=%s",
        rule_id,
        time_hhmm,
        applied or "unverändert",
    )
    return jsonify({
        "ok": True,
        "time_hhmm": time_hhmm,
        "applied_now": applied,
    })


@bp.post("/automation/<int:rule_id>/delete")
@roles_required("admin")
def delete_automation_rule(rule_id):
    db=get_db()
    rule = db.execute(
        "SELECT device_id FROM automation_rules WHERE id=?",
        (rule_id,),
    ).fetchone()
    affected_device_id = rule["device_id"] if rule else None
    db.execute("DELETE FROM automation_rules WHERE id=?",(rule_id,))
    db.commit()
    if affected_device_id is not None:
        reconcile_device_automation_now(
            current_app, db, affected_device_id
        )
    flash_i18n("Automation gelöscht und aktueller Zustand geprüft.","success")
    return redirect(url_for("main.automation_page"))

@bp.post("/automation/<int:rule_id>/run")
@roles_required("admin")
def run_automation_rule(rule_id):
    db=get_db()
    rule=db.execute(
        "SELECT id,device_id,action,time_hhmm,weekdays,last_fired_key "
        "FROM automation_rules WHERE id=?",(rule_id,)
    ).fetchone()
    if rule is None:
        flash_i18n("Automation nicht gefunden.","error")
        return redirect(url_for("main.automation_page"))
    try:
        execute_rule(current_app,db,rule)
        flash_i18n("Automation testweise ausgeführt.","success")
    except Exception as exc:
        current_app.logger.exception("Automation-Test fehlgeschlagen")
        flash_i18n(f"Automation fehlgeschlagen: {exc}","error")
    return redirect(url_for("main.automation_page"))


@bp.get("/settings")
@roles_required("admin")
def settings_hub():
    return render_template("settings.html")




@bp.post("/settings/language")
@roles_required("admin")
def update_language():
    language = request.form.get("language", "").strip().lower()
    if language not in SUPPORTED_LANGUAGES:
        flash_i18n(t("settings.language_invalid"), "error")
        return redirect(url_for("main.settings_hub"))
    set_language(language)
    # The flash is resolved after saving so it appears in the newly selected language.
    flash_i18n(t("settings.language_saved"), "success")
    return redirect(url_for("main.settings_hub"))

@bp.get("/settings/router")
@roles_required("admin")
def router_config_page():
    choices = []
    for manifest_path in sorted(Path(current_app.config["ADDONS_DIR"]).glob("*/manifest.json")):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            choices.append({"id": manifest["id"], "name": manifest["name"]})
        except Exception:
            continue
    return render_template(
        "router_config.html",
        addon_choices=choices,
        current_addon=str(current_app.config.get("WANSINN_ADDON", "")),
        router_host=str(current_app.config.get("MIKROTIK_HOST", "")),
        router_user=str(current_app.config.get("MIKROTIK_USER", "")),
        router_port=int(current_app.config.get("MIKROTIK_PORT", 22)),
        ssh_key=str(current_app.config.get("MIKROTIK_SSH_KEY", "")),
        known_hosts=str(current_app.config.get("MIKROTIK_KNOWN_HOSTS", "")),
    )


@bp.post("/settings/router")
@roles_required("admin")
def update_router_config():
    addon_id = request.form.get("addon", "").strip()
    password = request.form.get("router_password", "")
    try:
        host = validate_private_ipv4(request.form.get("host", "").strip())
        user = request.form.get("router_user", "").strip()
        if not USERNAME_RE.fullmatch(user):
            raise ValueError("Router-Benutzername ist ungültig.")
        port = int(request.form.get("port", "22"))
        if not 1 <= port <= 65535:
            raise ValueError("SSH-Port ist ungültig.")

        addons_dir = Path(current_app.config["ADDONS_DIR"])
        manifest = addons_dir / addon_id / "manifest.json"
        if not manifest.exists():
            raise ValueError("Router-Add-on wurde nicht gefunden.")
        if addon_id == "glinet" and request.form.get("glinet_takeover_ack") != "1":
            raise ValueError("GL.iNet Exclusive Control muss bestätigt werden.")

        key_path = Path(current_app.config["MIKROTIK_SSH_KEY"])
        known_hosts = Path(current_app.config["MIKROTIK_KNOWN_HOSTS"])

        # For MikroTik, an entered password explicitly requests bootstrap/re-key.
        # Without a password we test the existing key against the new target.
        if password:
            if addon_id == "mikrotik":
                _bootstrap_mikrotik(host, user, password, port, key_path, known_hosts)
            elif addon_id == "glinet":
                _bootstrap_openwrt(host, user, password, port, key_path, known_hosts)

        candidate_config = dict(current_app.config)
        candidate_config.update(
            WANSINN_ADDON=addon_id,
            MIKROTIK_HOST=host,
            MIKROTIK_USER=user,
            MIKROTIK_PORT=port,
        )

        # Build candidate against a tiny proxy carrying the candidate config.
        class _CandidateApp:
            def __init__(self, real_app, config):
                self.config = config
                self.logger = real_app.logger

        candidate = load_addon(addon_id, addons_dir, _CandidateApp(current_app, candidate_config))
        result = candidate.test_connection()
        if not result.get("ok"):
            raise RuntimeError(result.get("error") or "Router-Verbindung konnte nicht bestätigt werden.")

        env_path = Path(current_app.config["PROJECT_ROOT"]) / ".env"
        env_lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
        updates = {
            "WANSINN_ADDON": addon_id,
            "MIKROTIK_HOST": host,
            "MIKROTIK_USER": user,
            "MIKROTIK_PORT": str(port),
        }
        seen = set()
        new_lines = []
        for line in env_lines:
            key = line.split("=", 1)[0] if "=" in line else ""
            if key in updates:
                new_lines.append(f"{key}={updates[key]}")
                seen.add(key)
            else:
                new_lines.append(line)
        for key, value in updates.items():
            if key not in seen:
                new_lines.append(f"{key}={value}")
        env_path.write_text("\n".join(new_lines).rstrip() + "\n", encoding="utf-8")

        current_app.config.update(
            WANSINN_ADDON=addon_id,
            MIKROTIK_HOST=host,
            MIKROTIK_USER=user,
            MIKROTIK_PORT=port,
        )
        current_app.extensions["wansinn_addon"] = load_addon(addon_id, addons_dir, current_app)
        takeover = getattr(current_app.extensions["wansinn_addon"], "take_control", None)
        if callable(takeover):
            takeover(force_snapshot=True)
        current_app.extensions.pop("wansinn_health_runtime", None)
        flash_i18n("Routerkonfiguration getestet und übernommen.", "success")
    except Exception as exc:
        current_app.logger.exception("Routerkonfiguration konnte nicht übernommen werden")
        flash_i18n(f"Routerkonfiguration nicht geändert: {exc}", "error")
    finally:
        password = ""

    return redirect(url_for("main.router_config_page"))


@bp.get("/config")
@roles_required("admin")
def config_page():
    api_token = get_db().execute(
        "SELECT token_prefix,created_at,last_used_at FROM api_tokens WHERE id=1"
    ).fetchone()
    return render_template(
        "config.html",
        infrastructure_addresses=_infrastructure_rows(),
        management_ip=str(current_app.config.get("WANSINN_MANAGEMENT_IP", "")).strip(),
        testing_ip=str(current_app.config.get("WANSINN_TESTING_IP", "")).strip(),
        api_token=api_token,
        new_api_token=session.pop("new_api_token", None),
    )


@bp.post("/config/api-token/generate")
@roles_required("admin")
def generate_api_token():
    token = "wansinn_" + secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    prefix = token[:16]

    db = get_db()
    db.execute(
        """
        INSERT INTO api_tokens(id,token_hash,token_prefix,created_at,last_used_at)
        VALUES(1,?,?,CURRENT_TIMESTAMP,'')
        ON CONFLICT(id) DO UPDATE SET
            token_hash=excluded.token_hash,
            token_prefix=excluded.token_prefix,
            created_at=CURRENT_TIMESTAMP,
            last_used_at=''
        """,
        (token_hash, prefix),
    )
    db.commit()

    # The clear-text token is intentionally available for exactly one page load.
    session["new_api_token"] = token
    current_app.logger.warning(
        "API: Zugriffstoken durch %s neu erzeugt",
        g.user["username"],
    )
    flash_i18n(
        "API-Token erzeugt. Jetzt kopieren – er wird danach nicht erneut angezeigt.",
        "success",
    )
    return redirect(url_for("main.config_page"))


@bp.post("/config/api-token/revoke")
@roles_required("admin")
def revoke_api_token():
    db = get_db()
    db.execute("DELETE FROM api_tokens WHERE id=1")
    db.commit()
    session.pop("new_api_token", None)
    current_app.logger.warning(
        "API: Zugriffstoken durch %s widerrufen",
        g.user["username"],
    )
    flash_i18n("API-Token widerrufen. API-Zugriffe sind jetzt deaktiviert.", "success")
    return redirect(url_for("main.config_page"))


@bp.post("/config/infrastructure")
@roles_required("admin")
def update_infrastructure_addresses():
    db = get_db()
    management_ip = str(current_app.config.get("WANSINN_MANAGEMENT_IP", "")).strip()
    testing_ip = str(current_app.config.get("WANSINN_TESTING_IP", "")).strip()
    automatically_reserved = {ip for ip in (management_ip, testing_ip) if ip}

    # Browser sends row_0_ip/name/note, row_1_..., etc.
    indexes = sorted({
        match.group(1)
        for key in request.form.keys()
        if (match := re.fullmatch(r"infra_(\d+)_ip", key))
    }, key=int)

    records = []
    seen = set()
    try:
        for index in indexes:
            raw_ip = request.form.get(f"infra_{index}_ip", "").strip()
            name = request.form.get(f"infra_{index}_name", "").strip()
            note = request.form.get(f"infra_{index}_note", "").strip()

            # Completely empty rows are UI placeholders and are ignored.
            if not raw_ip and not name and not note:
                continue
            if not raw_ip:
                raise ValueError(
                    f"Infrastruktur-Zeile {int(index) + 1}: IP-Adresse fehlt."
                )

            ip = validate_private_ipv4(raw_ip)
            if ip in automatically_reserved:
                raise ValueError(
                    f"{ip} ist bereits als Management-/Prüf-IP automatisch reserviert."
                )
            if ip in seen:
                raise ValueError(f"{ip} ist doppelt eingetragen.")
            seen.add(ip)

            records.append((ip, name[:80], note[:240]))
    except ValueError as exc:
        flash_i18n(f"Infrastruktur nicht gespeichert: {exc}", "error")
        return redirect(url_for("main.device_management"))

    try:
        # Replace the full editor state atomically.
        db.execute("BEGIN")
        db.execute("DELETE FROM infrastructure_addresses")
        for ip, name, note in records:
            db.execute(
                """
                INSERT INTO infrastructure_addresses(ip,name,note,updated_at)
                VALUES(?,?,?,CURRENT_TIMESTAMP)
                """,
                (ip, name, note),
            )

        ips = [ip for ip, _name, _note in records]
        removed_devices = 0
        if ips:
            placeholders = ",".join("?" for _ in ips)
            removed_devices = db.execute(
                f"DELETE FROM devices WHERE ip IN ({placeholders})",
                tuple(ips),
            ).rowcount
            db.execute(
                f"DELETE FROM discovered_devices WHERE ip IN ({placeholders})",
                tuple(ips),
            )

        db.commit()

        current_app.logger.warning(
            "CONFIG: Infrastruktur aktualisiert: %s",
            ", ".join(
                f"{name or 'Ohne Name'} ({ip})" for ip, name, _note in records
            ) if records else "keine manuellen Einträge",
        )
        if removed_devices:
            current_app.logger.warning(
                "CONFIG: %s bereits verwaltete Infrastruktur-Gerät(e) entfernt",
                removed_devices,
            )
        flash_i18n(
            f"Infrastruktur gespeichert ({len(records)} Einträge).",
            "success",
        )
    except Exception as exc:
        db.rollback()
        current_app.logger.exception("Infrastruktur konnte nicht gespeichert werden")
        flash_i18n(f"Infrastruktur nicht gespeichert: {exc}", "error")

    return redirect(url_for("main.device_management"))


def _version_key(value: str) -> tuple[int, ...]:
    value = value.strip().lstrip("vV")
    if not re.fullmatch(r"\d+(?:[.-]\d+)*", value):
        raise ValueError(f"Ungültige Versionsnummer: {value}")
    return tuple(int(part) for part in re.split(r"[.-]", value))


def _safe_update_members(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = []
    for info in zf.infolist():
        raw = info.filename.replace("\\", "/")
        path = Path(raw)
        if not raw or raw.startswith("/") or ".." in path.parts:
            raise ValueError("Update-ZIP enthält einen unsicheren Dateipfad.")
        # Reject Unix symlink entries.
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            raise ValueError("Update-ZIP darf keine Symlinks enthalten.")
        members.append(info)
    return members


def _update_archive_root(zf: zipfile.ZipFile) -> str:
    files = [info.filename.replace("\\", "/") for info in _safe_update_members(zf) if not info.is_dir()]
    roots = {name.split("/", 1)[0] for name in files if "/" in name}
    if len(roots) == 1:
        root = next(iter(roots))
        required = {
            f"{root}/VERSION",
            f"{root}/run.py",
            f"{root}/start.sh",
            f"{root}/stop.sh",
            f"{root}/wansinn/__init__.py",
        }
        if required.issubset(set(files)):
            return root + "/"

    required = {"VERSION", "run.py", "start.sh", "stop.sh", "wansinn/__init__.py"}
    if required.issubset(set(files)):
        return ""
    raise ValueError("ZIP ist kein gültiges WANSINN-Update-Paket.")


@bp.get("/update-probe")
def update_probe():
    """Lightweight unauthenticated probe used only for local update handoff.

    The update wait page must distinguish the old still-running process from
    the newly started target version. Returning the active application
    version makes that handoff deterministic instead of treating any HTTP 200
    response as success.
    """
    return jsonify({
        "ok": True,
        "version": current_app.config.get("WANSINN_VERSION", ""),
    })


@bp.post("/update")
@roles_required("admin")
def install_update():
    upload = request.files.get("update_file")
    if upload is None or not upload.filename:
        flash_i18n("Bitte ein WANSINN-ZIP auswählen.", "error")
        return redirect(url_for("main.config_page"))

    filename = upload.filename.lower()
    if not filename.endswith(".zip"):
        flash_i18n("Update-Paket muss eine .zip-Datei sein.", "error")
        return redirect(url_for("main.config_page"))

    project_root = Path(current_app.config["PROJECT_ROOT"]).resolve()
    parent = project_root.parent
    staging_parent = parent / ".wansinn-updates"
    staging_parent.mkdir(parents=True, exist_ok=True)

    package_path = staging_parent / "incoming.zip"
    upload.save(package_path)

    # Avoid accidentally accepting huge arbitrary uploads.
    if package_path.stat().st_size > 200 * 1024 * 1024:
        package_path.unlink(missing_ok=True)
        flash_i18n("Update-Paket ist größer als 200 MB.", "error")
        return redirect(url_for("main.config_page"))

    try:
        with zipfile.ZipFile(package_path) as zf:
            archive_root = _update_archive_root(zf)
            version_member = archive_root + "VERSION"
            target_version = zf.read(version_member).decode("utf-8").strip()
            current_version = current_app.config["WANSINN_VERSION"]

            if _version_key(target_version) <= _version_key(current_version):
                raise ValueError(
                    f"Update muss neuer sein als {current_version}; Paket enthält {target_version}."
                )

            final_dir = parent / f"WANSINN-v{target_version}"
            if final_dir.exists():
                raise ValueError(f"Zielverzeichnis existiert bereits: {final_dir.name}")

            staging_dir = staging_parent / f"WANSINN-v{target_version}.staged"
            if staging_dir.exists():
                shutil.rmtree(staging_dir)
            staging_dir.mkdir(parents=True)

            prefix_len = len(archive_root)
            for info in _safe_update_members(zf):
                name = info.filename.replace("\\", "/")
                if archive_root and not name.startswith(archive_root):
                    continue
                relative = name[prefix_len:] if archive_root else name
                if not relative:
                    continue
                destination = staging_dir / relative
                if info.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, destination.open("wb") as dst:
                    shutil.copyfileobj(src, dst)

        # Preserve executable bits for the known scripts.
        for script in ("start.sh", "stop.sh", "install.sh", "configure.sh", "doctor.sh", "update_worker.py"):
            p = staging_dir / script
            if p.exists():
                p.chmod(p.stat().st_mode | 0o755)

        # Rename staged tree atomically into its final sibling path before
        # shutdown. Persistent state is copied by the worker only after stop.
        staging_dir.replace(final_dir)

        status_file = parent / ".wansinn-update-status.json"
        worker = project_root / "update_worker.py"
        worker_log = parent / ".wansinn-update-worker.log"
        log_handle = worker_log.open("a", encoding="utf-8")
        subprocess.Popen(
            [
                str(project_root / ".venv/bin/python"),
                str(worker),
                "--current", str(project_root),
                "--target", str(final_dir),
                "--status", str(status_file),
                "--version", target_version,
            ],
            cwd=project_root,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )

        return render_template(
            "update_wait.html",
            target_version=target_version,
            current_version=current_version,
        )
    except (ValueError, zipfile.BadZipFile, UnicodeDecodeError, OSError) as exc:
        current_app.logger.exception("Update-Paket wurde abgelehnt")
        flash_i18n(f"Update nicht gestartet: {exc}", "error")
        return redirect(url_for("main.config_page"))
    finally:
        package_path.unlink(missing_ok=True)




def _config_profile_ids() -> set[str]:
    return {
        row["profile_id"]
        for row in get_db().execute(
            "SELECT profile_id FROM route_profiles"
        ).fetchall()
    }


def _validate_config_v2(payload: dict) -> tuple[dict, list[str]]:
    errors: list[str] = []

    devices_raw = payload.get("devices", [])
    profiles_raw = payload.get("wan_profiles", [])
    states_raw = payload.get("auto_states", [])

    if not isinstance(devices_raw, list):
        return {}, ["Das Feld 'devices' fehlt oder ist ungültig."]
    if not isinstance(profiles_raw, list):
        return {}, ["Das Feld 'wan_profiles' fehlt oder ist ungültig."]
    if not isinstance(states_raw, list):
        return {}, ["Das Feld 'auto_states' fehlt oder ist ungültig."]

    clean_profiles = []
    profile_ids = set()

    for index, item in enumerate(profiles_raw, start=1):
        if not isinstance(item, dict):
            errors.append(f"WAN-Profil {index}: ungültiges Format.")
            continue

        profile_id = str(item.get("id", "")).strip().lower()
        label = str(item.get("label", "")).strip()
        color = str(item.get("color", "#6f7d90")).strip().lower()

        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", profile_id):
            errors.append(f"WAN-Profil {index}: ungültige Profil-ID.")
            continue
        if profile_id in {"auto", "offline"}:
            errors.append(f"WAN-Profil {index}: reservierte Profil-ID.")
            continue
        if profile_id in profile_ids:
            errors.append(f"WAN-Profil {index}: Profil-ID {profile_id} ist doppelt.")
            continue
        if not label:
            errors.append(f"WAN-Profil {index}: Name fehlt.")
            continue
        if not re.fullmatch(r"#[0-9a-f]{6}", color):
            errors.append(f"WAN-Profil {index}: ungültige Farbe {color}.")
            continue

        try:
            gateway = validate_private_ipv4(str(item.get("gateway", "")).strip())
            health_target = validate_probe_ipv4(
                str(item.get("health_target", "1.1.1.1")).strip()
            )
            health_interval = int(item.get("health_interval", 10))
            health_timeout = int(item.get("health_timeout", 2))
            fail_threshold = int(item.get("fail_threshold", 3))
            recover_threshold = int(item.get("recover_threshold", 2))
        except (ValueError, TypeError) as exc:
            errors.append(f"WAN-Profil {index}: {exc}")
            continue

        if not 2 <= health_interval <= 300:
            errors.append(f"WAN-Profil {index}: Health-Intervall außerhalb 2–300 s.")
            continue
        if not 1 <= health_timeout <= 10:
            errors.append(f"WAN-Profil {index}: Timeout außerhalb 1–10 s.")
            continue
        if not 1 <= fail_threshold <= 10:
            errors.append(f"WAN-Profil {index}: Fail-Schwelle außerhalb 1–10.")
            continue
        if not 1 <= recover_threshold <= 10:
            errors.append(f"WAN-Profil {index}: Recover-Schwelle außerhalb 1–10.")
            continue

        profile_ids.add(profile_id)
        clean_profiles.append({
            "id": profile_id,
            "label": label[:80],
            "gateway": gateway,
            "color": color,
            "health_target": health_target,
            "health_interval": health_interval,
            "health_timeout": health_timeout,
            "fail_threshold": fail_threshold,
            "recover_threshold": recover_threshold,
            "enabled": bool(item.get("enabled", True)),
        })

    clean_devices = []
    device_ips = set()

    for index, item in enumerate(devices_raw, start=1):
        if not isinstance(item, dict):
            errors.append(f"Gerät {index}: ungültiges Format.")
            continue

        name = str(item.get("name", "")).strip()
        note = str(item.get("note", "")).strip()
        logical_profile = str(item.get("profile", "auto")).strip().lower()
        mac_raw = str(item.get("mac", "") or "").strip()

        try:
            ip = validate_private_ipv4(str(item.get("ip", "")).strip())
            mac = validate_mac(mac_raw) if mac_raw else None
        except ValueError as exc:
            errors.append(f"Gerät {index}: {exc}")
            continue

        if not name:
            errors.append(f"Gerät {index}: Name fehlt.")
            continue
        if ip in device_ips:
            errors.append(f"Gerät {index}: IP {ip} ist doppelt.")
            continue
        if logical_profile not in profile_ids | {"auto", "offline"}:
            errors.append(
                f"Gerät {index}: unbekanntes Profil {logical_profile!r}."
            )
            continue

        device_ips.add(ip)
        clean_devices.append({
            "name": name[:80],
            "ip": ip,
            "note": note[:200],
            "profile": logical_profile,
            "mac": mac,
        })

    clean_states = []
    availability_signatures = set()

    for index, item in enumerate(states_raw, start=1):
        if not isinstance(item, dict):
            errors.append(f"AUTO-Zustand {index}: ungültiges Format.")
            continue

        name = str(item.get("name", "")).strip() or f"AUTO-Zustand {index}"
        availability = item.get("availability", {})
        mappings = item.get("devices", {})

        if not isinstance(availability, dict):
            errors.append(f"AUTO-Zustand {index}: 'availability' ist ungültig.")
            continue
        if not isinstance(mappings, dict):
            errors.append(f"AUTO-Zustand {index}: 'devices' ist ungültig.")
            continue

        availability_clean = {}
        for profile_id in profile_ids:
            value = availability.get(profile_id, False)
            if not isinstance(value, bool):
                errors.append(
                    f"AUTO-Zustand {index}: Verfügbarkeit von {profile_id} ist nicht boolesch."
                )
                continue
            availability_clean[profile_id] = value

        unknown_availability = set(availability) - profile_ids
        if unknown_availability:
            errors.append(
                f"AUTO-Zustand {index}: unbekannte WANs in availability: "
                + ", ".join(sorted(unknown_availability))
            )
            continue

        mapping_clean = {}
        mapping_error = False
        for ip_raw, target_raw in mappings.items():
            try:
                ip = validate_private_ipv4(str(ip_raw).strip())
            except ValueError:
                errors.append(
                    f"AUTO-Zustand {index}: ungültige Geräte-IP {ip_raw!r}."
                )
                mapping_error = True
                continue

            target = str(target_raw).strip().lower()
            if ip not in device_ips:
                errors.append(
                    f"AUTO-Zustand {index}: Gerät {ip} ist nicht in devices enthalten."
                )
                mapping_error = True
                continue
            if target not in profile_ids | {"offline"}:
                errors.append(
                    f"AUTO-Zustand {index}: ungültiges Ziel {target!r} für {ip}."
                )
                mapping_error = True
                continue
            mapping_clean[ip] = target

        if mapping_error:
            continue

        signature = _availability_key(availability_clean)
        if signature in availability_signatures:
            errors.append(
                f"AUTO-Zustand {index}: WAN-Kombination ist doppelt vorhanden."
            )
            continue
        availability_signatures.add(signature)

        clean_states.append({
            "name": name[:80],
            "availability": availability_clean,
            "devices": mapping_clean,
        })

    return {
        "config_version": 2,
        "devices": clean_devices,
        "wan_profiles": clean_profiles,
        "auto_states": clean_states,
        "installation": payload.get("installation", {}),
    }, errors


@bp.get("/config/export")
@roles_required("admin")
def export_config():
    _sync_route_profile_metadata()
    db = get_db()

    profile_rows = db.execute(
        """
        SELECT profile_id,label,color,gateway,
               health_target,health_interval,health_timeout,
               fail_threshold,recover_threshold,enabled
        FROM route_profiles
        ORDER BY label COLLATE NOCASE
        """
    ).fetchall()

    device_rows = db.execute(
        """
        SELECT id,name,ip,note,wan_profile,mac
        FROM devices
        ORDER BY name COLLATE NOCASE
        """
    ).fetchall()

    state_rows = db.execute(
        """
        SELECT id,name,availability_key
        FROM auto_states
        ORDER BY id
        """
    ).fetchall()

    id_to_ip = {row["id"]: row["ip"] for row in device_rows}
    profile_ids = [row["profile_id"] for row in profile_rows]

    states = []
    for state in state_rows:
        availability = {profile_id: False for profile_id in profile_ids}
        for token in state["availability_key"].split(","):
            if "=" not in token:
                continue
            profile_id, value = token.split("=", 1)
            if profile_id in availability:
                availability[profile_id] = value == "1"

        mapping_rows = db.execute(
            """
            SELECT device_id,profile_id
            FROM auto_state_device_routes
            WHERE state_id=?
            """,
            (state["id"],),
        ).fetchall()

        mappings = {
            id_to_ip[row["device_id"]]: row["profile_id"]
            for row in mapping_rows
            if row["device_id"] in id_to_ip
        }

        states.append({
            "name": state["name"],
            "availability": availability,
            "devices": mappings,
        })

    groups = []
    for group in db.execute("SELECT id,name,note FROM device_groups ORDER BY name COLLATE NOCASE").fetchall():
        members = db.execute("""
            SELECT d.ip FROM device_group_members m
            JOIN devices d ON d.id=m.device_id
            WHERE m.group_id=? ORDER BY d.name COLLATE NOCASE
        """,(group["id"],)).fetchall()
        groups.append({"name":group["name"],"note":group["note"],
                       "devices":[row["ip"] for row in members]})

    automation_windows = [{
        "device_ip": row["ip"], "mode": row["mode"],
        "start_hhmm": row["start_hhmm"], "end_hhmm": row["end_hhmm"],
        "weekdays": row["weekdays"], "active": bool(row["active"])
    } for row in db.execute("""
        SELECT w.*,d.ip FROM automation_windows w
        JOIN devices d ON d.id=w.device_id ORDER BY w.id
    """).fetchall()]

    infrastructure_addresses = [dict(row) for row in db.execute(
        "SELECT ip,name,note FROM infrastructure_addresses ORDER BY ip"
    ).fetchall()]

    payload = {
        "format": "wansinn-config",
        "config_version": 3,
        "wansinn_version": current_app.config["WANSINN_VERSION"],
        "installation": {
            # Metadata only. Import deliberately does not apply these.
            "management_ip": current_app.config.get("WANSINN_MANAGEMENT_IP", ""),
            "testing_ip": current_app.config.get("WANSINN_TESTING_IP", ""),
        },
        "wan_profiles": [
            {
                "id": row["profile_id"],
                "label": row["label"],
                "gateway": row["gateway"],
                "color": row["color"],
                "health_target": row["health_target"],
                "health_interval": row["health_interval"],
                "health_timeout": row["health_timeout"],
                "fail_threshold": row["fail_threshold"],
                "recover_threshold": row["recover_threshold"],
                "enabled": bool(row["enabled"]),
            }
            for row in profile_rows
        ],
        "devices": [
            {
                "name": row["name"],
                "ip": row["ip"],
                "note": row["note"],
                "profile": row["wan_profile"],
                "mac": row["mac"],
            }
            for row in device_rows
        ],
        "auto_states": states,
        "device_groups": groups,
        "automation_windows": automation_windows,
        "infrastructure_addresses": infrastructure_addresses,
    }

    content = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    return send_file(
        BytesIO(content),
        mimetype="application/json",
        as_attachment=True,
        download_name="WANSINN.cfg",
        max_age=0,
    )


@bp.post("/config/import/preview")
@roles_required("admin")
def import_config_preview():
    uploaded = request.files.get("config_file")
    if uploaded is None or not uploaded.filename:
        flash_i18n("Bitte eine WANSINN.cfg auswählen.", "error")
        return redirect(url_for("main.config_page"))

    try:
        raw = uploaded.read()
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("Die Konfigurationsdatei ist zu groß.")

        payload = json.loads(raw.decode("utf-8"))
        version = payload.get("config_version")

        if version == 1:
            # Backward compatibility with old WANSINN.cfg device-only files.
            devices = payload.get("devices")
            if not isinstance(devices, list):
                raise ValueError("Das Feld 'devices' fehlt oder ist ungültig.")
            payload = {
                "format": "wansinn-config",
                "config_version": 2,
                "installation": {},
                "wan_profiles": [],
                "auto_states": [],
                "devices": [
                    {
                        "name": item.get("name", ""),
                        "ip": item.get("ip", ""),
                        "note": item.get("note", ""),
                        "profile": "auto",
                    }
                    for item in devices
                    if isinstance(item, dict)
                ],
            }
        elif version not in {2, 3}:
            raise ValueError("Nicht unterstützte Config-Version.")

        clean_payload, errors = _validate_config_v2(payload)
        if version == 3:
            clean_payload["config_version"] = 3
            clean_payload["device_groups"] = payload.get("device_groups", [])
            clean_payload["automation_windows"] = payload.get("automation_windows", [])
            clean_payload["infrastructure_addresses"] = payload.get("infrastructure_addresses", [])
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        flash_i18n(f"Import fehlgeschlagen: {exc}", "error")
        return redirect(url_for("main.config_page"))

    db = get_db()
    existing_devices = {
        row["ip"]: row
        for row in db.execute(
            "SELECT name,ip,note,wan_profile,mac FROM devices"
        ).fetchall()
    }
    existing_profiles = {
        row["profile_id"]: row
        for row in db.execute(
            """
            SELECT profile_id,label,color,gateway,
                   health_target,health_interval,health_timeout,
                   fail_threshold,recover_threshold
            FROM route_profiles
            """
        ).fetchall()
    }

    device_new = []
    device_updates = []
    device_unchanged = []
    for item in clean_payload["devices"]:
        existing = existing_devices.get(item["ip"])
        if existing is None:
            device_new.append(item)
        elif (
            existing["name"] == item["name"]
            and existing["note"] == item["note"]
            and existing["wan_profile"] == item["profile"]
            and (existing["mac"] or None) == item.get("mac")
        ):
            device_unchanged.append(item)
        else:
            device_updates.append(item)

    profile_new = []
    profile_updates = []
    profile_unchanged = []
    for item in clean_payload["wan_profiles"]:
        existing = existing_profiles.get(item["id"])
        if existing is None:
            profile_new.append(item)
            continue

        same = all([
            existing["label"] == item["label"],
            existing["color"] == item["color"],
            existing["gateway"] == item["gateway"],
            existing["health_target"] == item["health_target"],
            int(existing["health_interval"]) == item["health_interval"],
            int(existing["health_timeout"]) == item["health_timeout"],
            int(existing["fail_threshold"]) == item["fail_threshold"],
            int(existing["recover_threshold"]) == item["recover_threshold"],
        ])
        (profile_unchanged if same else profile_updates).append(item)

    return render_template(
        "config_preview.html",
        errors=errors,
        config_version=2,
        imported_payload=json.dumps(clean_payload, ensure_ascii=False),
        new_devices=device_new,
        updates=device_updates,
        unchanged=device_unchanged,
        new_profiles=profile_new,
        updated_profiles=profile_updates,
        unchanged_profiles=profile_unchanged,
        auto_states=clean_payload["auto_states"],
        source_installation=clean_payload.get("installation") or {},
    )


@bp.post("/config/import/apply")
@roles_required("admin")
def import_config_apply():
    try:
        payload = json.loads(request.form.get("payload", ""))
        clean_payload, errors = _validate_config_v2(payload)
        if payload.get("config_version") == 3:
            clean_payload["config_version"] = 3
            clean_payload["device_groups"] = payload.get("device_groups", [])
            clean_payload["automation_windows"] = payload.get("automation_windows", [])
            clean_payload["infrastructure_addresses"] = payload.get("infrastructure_addresses", [])
        if errors:
            raise ValueError("; ".join(errors[:5]))
    except (json.JSONDecodeError, ValueError) as exc:
        flash_i18n(f"Importdaten sind ungültig oder abgelaufen: {exc}", "error")
        return redirect(url_for("main.config_page"))

    mode = request.form.get("mode", "merge")
    if mode not in {"new-only", "merge", "replace"}:
        flash_i18n("Ungültiger Importmodus.", "error")
        return redirect(url_for("main.config_page"))

    db = get_db()

    try:
        # 1. WAN profiles first, because device and AUTO mappings can refer to them.
        existing_profile_ids = {
            row["profile_id"]
            for row in db.execute(
                "SELECT profile_id FROM route_profiles"
            ).fetchall()
        }

        profiles_added = profiles_updated = profiles_skipped = 0

        for profile in clean_payload["wan_profiles"]:
            exists = profile["id"] in existing_profile_ids

            if not exists:
                # Use the ID as RouterOS profile name so the generated
                # force-/via- objects are deterministic and portable.
                created = addon().create_route_profile(
                    profile["id"],
                    profile["gateway"],
                )
                if created["id"] != profile["id"]:
                    raise RuntimeError(
                        f"Profil {profile['id']} wurde mit unerwarteter ID angelegt."
                    )
                existing_profile_ids.add(profile["id"])
                profiles_added += 1
            elif mode == "new-only":
                profiles_skipped += 1
                continue
            else:
                # create_route_profile is also our conflict verifier. It will
                # refuse an existing profile with a different gateway.
                addon().create_route_profile(
                    profile["id"],
                    profile["gateway"],
                )
                profiles_updated += 1

            db.execute(
                """
                INSERT INTO route_profiles(
                    profile_id,label,color,gateway,
                    health_target,health_interval,health_timeout,
                    fail_threshold,recover_threshold,
                    health_status,health_fail_count,health_ok_count,
                    health_last_check,health_last_change
                )
                VALUES(?,?,?,?,?,?,?,?,?,'unknown',0,0,'','')
                ON CONFLICT(profile_id) DO UPDATE SET
                    label=excluded.label,
                    color=excluded.color,
                    gateway=excluded.gateway,
                    health_target=excluded.health_target,
                    health_interval=excluded.health_interval,
                    health_timeout=excluded.health_timeout,
                    fail_threshold=excluded.fail_threshold,
                    recover_threshold=excluded.recover_threshold,
                    health_status='unknown',
                    health_fail_count=0,
                    health_ok_count=0,
                    health_last_check='',
                    health_last_change=''
                """,
                (
                    profile["id"],
                    profile["label"],
                    profile["color"],
                    profile["gateway"],
                    profile["health_target"],
                    profile["health_interval"],
                    profile["health_timeout"],
                    profile["fail_threshold"],
                    profile["recover_threshold"],
                ),
            )

        # 2. Replace mode replaces logical WANSINN policy data, but never
        # deletes router profiles that are absent from the file. That would be
        # too destructive for an import operation.
        if mode == "replace":
            db.execute("DELETE FROM auto_state_device_routes")
            db.execute("DELETE FROM auto_states")
            db.execute("DELETE FROM devices")

        # 3. Devices.
        added = updated = skipped = 0
        for item in clean_payload["devices"]:
            existing = db.execute(
                "SELECT id FROM devices WHERE ip=?",
                (item["ip"],),
            ).fetchone()

            if existing is None:
                db.execute(
                    """
                    INSERT INTO devices(
                        name,ip,note,wan_profile,effective_profile,mac
                    )
                    VALUES(?,?,?,?,?,?)
                    """,
                    (
                        item["name"],
                        item["ip"],
                        item["note"],
                        "auto",
                        "auto",
                        item.get("mac"),
                    ),
                )
                added += 1
            elif mode == "merge":
                db.execute(
                    """
                    UPDATE devices
                    SET name=?,note=?,wan_profile='auto',
                        effective_profile='auto',mac=?,
                        manual_override='',manual_override_at='',
                        automation_override='',automation_override_at='',
                        updated_at=CURRENT_TIMESTAMP
                    WHERE ip=?
                    """,
                    (
                        item["name"],
                        item["note"],
                        item.get("mac"),
                        item["ip"],
                    ),
                )
                updated += 1
            else:
                skipped += 1

        # 4. AUTO states. Merge uses WAN signature as stable identity.
        state_added = state_updated = state_skipped = 0
        for state in clean_payload["auto_states"]:
            key = _availability_key(state["availability"])
            existing_state = db.execute(
                "SELECT id FROM auto_states WHERE availability_key=?",
                (key,),
            ).fetchone()

            if existing_state is None:
                cursor = db.execute(
                    "INSERT INTO auto_states(name,availability_key) VALUES(?,?)",
                    (state["name"], key),
                )
                state_id = cursor.lastrowid
                state_added += 1
            elif mode == "new-only":
                state_skipped += 1
                continue
            else:
                state_id = existing_state["id"]
                db.execute(
                    "UPDATE auto_states SET name=? WHERE id=?",
                    (state["name"], state_id),
                )
                db.execute(
                    "DELETE FROM auto_state_device_routes WHERE state_id=?",
                    (state_id,),
                )
                state_updated += 1

            for device_ip, target in state["devices"].items():
                device = db.execute(
                    "SELECT id,wan_profile FROM devices WHERE ip=?",
                    (device_ip,),
                ).fetchone()
                if device is None:
                    continue
                if device["wan_profile"] != "auto":
                    # Scenario mappings only apply to logical AUTO devices.
                    continue
                db.execute(
                    """
                    INSERT INTO auto_state_device_routes(
                        state_id,device_id,profile_id
                    )
                    VALUES(?,?,?)
                    """,
                    (state_id, device["id"], target),
                )

        # 4b. Config v3: restore portable WANSINN policy metadata.
        if clean_payload.get("config_version") == 3:
            if mode == "replace":
                db.execute("DELETE FROM device_group_members")
                db.execute("DELETE FROM device_groups")
                db.execute("DELETE FROM automation_rules WHERE window_id IS NOT NULL")
                db.execute("DELETE FROM automation_windows")
                db.execute("DELETE FROM infrastructure_addresses")

            for group in clean_payload.get("device_groups", []):
                name=str(group.get("name","")).strip()[:80]
                if not name: continue
                db.execute("""INSERT INTO device_groups(name,note) VALUES(?,?)
                    ON CONFLICT(name) DO UPDATE SET note=excluded.note,
                    updated_at=CURRENT_TIMESTAMP""",
                    (name,str(group.get("note","")).strip()))
                gid=db.execute("SELECT id FROM device_groups WHERE name=?",(name,)).fetchone()["id"]
                if mode != "new-only":
                    db.execute("DELETE FROM device_group_members WHERE group_id=?",(gid,))
                for ip in group.get("devices",[]):
                    d=db.execute("SELECT id FROM devices WHERE ip=?",(str(ip),)).fetchone()
                    if d: db.execute("INSERT OR IGNORE INTO device_group_members(group_id,device_id) VALUES(?,?)",(gid,d["id"]))

            for item in clean_payload.get("infrastructure_addresses",[]):
                ip=str(item.get("ip","")).strip()
                if ip:
                    db.execute("""INSERT INTO infrastructure_addresses(ip,name,note) VALUES(?,?,?)
                        ON CONFLICT(ip) DO UPDATE SET name=excluded.name,note=excluded.note""",
                        (ip,str(item.get("name","")).strip(),str(item.get("note","")).strip()))

            if mode != "new-only":
                for win in clean_payload.get("automation_windows",[]):
                    d=db.execute("SELECT id FROM devices WHERE ip=?",(str(win.get("device_ip","")).strip(),)).fetchone()
                    if not d: continue
                    cur=db.execute("""INSERT INTO automation_windows(device_id,mode,start_hhmm,end_hhmm,weekdays,active)
                        VALUES(?,?,?,?,?,?)""",(d["id"],str(win.get("mode","online")),
                        str(win.get("start_hhmm","07:00")),str(win.get("end_hhmm","19:00")),
                        str(win.get("weekdays","0,1,2,3,4")),1 if win.get("active",True) else 0))
                    _sync_automation_window_rules(db,cur.lastrowid)

        db.commit()

        # 5. Imported devices deliberately start in AUTO. The backup describes
        # policy/configuration, not stale physical router state.
        reconcile_auto_state(current_app, db)

    except Exception as exc:
        db.rollback()
        current_app.logger.exception("WANSINN.cfg Import fehlgeschlagen")
        flash_i18n(f"Import abgebrochen: {exc}", "error")
        return redirect(url_for("main.config_page"))

    flash_i18n(
        "Import abgeschlossen: "
        f"{profiles_added} WAN-Profil(e) neu, {profiles_updated} aktualisiert, "
        f"{added} Gerät(e) neu, {updated} aktualisiert, "
        f"{state_added} AUTO-Zustand/Zustände neu, {state_updated} aktualisiert.",
        "success",
    )
    return redirect(url_for("main.config_page"))
