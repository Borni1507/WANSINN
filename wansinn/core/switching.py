from __future__ import annotations

import logging


log = logging.getLogger(__name__)


class ProfileSwitchError(RuntimeError):
    pass


def _availability_key(availability: dict[str, bool]) -> str:
    return ",".join(
        f"{profile}={'1' if availability[profile] else '0'}"
        for profile in sorted(availability)
    )


def _resolve_auto_target(db, device_id: int) -> tuple[str, str]:
    """Resolve the current AUTO matrix to one concrete router profile.

    AUTO is a WANSINN control mode, not a router profile.  The router must
    always keep an effective WAN/OFFLINE policy for an AUTO device, otherwise
    Linux falls back to the router's native ``main`` table and GL.iNet's own
    Multi-WAN logic takes control.
    """
    rows = db.execute(
        "SELECT profile_id,health_status FROM route_profiles "
        "WHERE enabled=1 ORDER BY profile_id"
    ).fetchall()
    availability = {row["profile_id"]: row["health_status"] == "up" for row in rows}
    if not availability:
        raise ProfileSwitchError("AUTO kann ohne bekannte WAN-Zustände nicht aktiviert werden.")

    key = _availability_key(availability)
    state = db.execute(
        "SELECT id,name FROM auto_states WHERE availability_key=?", (key,)
    ).fetchone()
    if state is None:
        raise ProfileSwitchError(f"Kein AUTO-Zustand für {key} konfiguriert.")

    route = db.execute(
        "SELECT profile_id FROM auto_state_device_routes "
        "WHERE state_id=? AND device_id=?",
        (state["id"], device_id),
    ).fetchone()
    if route is None or not str(route["profile_id"]).strip():
        raise ProfileSwitchError(
            f"Für dieses Gerät ist im AUTO-Zustand ‚{state['name']}‘ kein Ziel konfiguriert."
        )

    target = str(route["profile_id"]).strip()
    if target != "offline" and not availability.get(target, False):
        raise ProfileSwitchError(
            f"AUTO-Ziel {target.upper()} ist laut Medic aktuell nicht verfügbar."
        )
    return target, str(state["name"])


def switch_device_profile(
    app,
    db,
    device,
    target: str,
    *,
    source: str = "MANUAL",
    allow_offline: bool = False,
    allow_release_offline: bool = False,
    verify: bool = False,
) -> str:
    """Single logical profile switch entry point for WANSINN.

    Web UI, scheduler and future API callers should use this function.
    AUTO failover remains separate because it changes only effective_profile.
    """
    addon = app.extensions.get("wansinn_addon")
    if addon is None:
        raise ProfileSwitchError("Router-Add-on ist nicht geladen.")

    valid_profiles = {"auto", "offline"} | {
        row["profile_id"]
        for row in db.execute(
            "SELECT profile_id FROM route_profiles WHERE managed=1 AND enabled=1"
        ).fetchall()
    }
    if target not in valid_profiles:
        raise ProfileSwitchError("Ungültiges Profil.")

    if target == "offline" and not allow_offline:
        raise ProfileSwitchError(
            "OFFLINE muss über eine autorisierte Sicherheitsaktion aktiviert werden."
        )

    if device["wan_profile"] == "offline" and target != "offline" and not allow_release_offline:
        raise ProfileSwitchError(
            "OFFLINE kann nur durch einen Administrator aufgehoben werden."
        )

    if target == "auto" and bool(device["router_imported"]):
        raise ProfileSwitchError(
            "AUTO ist für automatisch übernommene Router-Policies gesperrt. "
            "Das Gerät hat noch keine AUTO-Zuordnungen in der Redundanzmatrix."
        )

    requested = target
    auto_state_name = ""
    if requested == "auto":
        # AUTO stays owned by WANSINN.  Resolve the matrix to a concrete
        # effective profile and keep that policy installed on the router.
        # Never call set_device_profile(..., "auto") for a managed AUTO
        # device: on OpenWrt that intentionally releases the PBR rule to
        # ``main`` and hands control back to the native Multi-WAN stack.
        target, auto_state_name = _resolve_auto_target(db, device["id"])
        addon.apply_effective_profile(device["ip"], target)
    else:
        addon.set_device_profile(device["ip"], target)

    if verify:
        actual = addon.get_device_profile(device["ip"])
        if actual != target:
            raise ProfileSwitchError(
                f"Router-Readback meldet {actual.upper()} statt {target.upper()}."
            )

    db.execute(
        """
        UPDATE devices
        SET wan_profile=?, effective_profile=?,
            automation_override='', automation_override_at='',
            updated_at=CURRENT_TIMESTAMP
        WHERE id=?
        """,
        (requested, target, device["id"]),
    )
    db.commit()

    if requested == "auto":
        log.warning(
            "%s: %s (%s) -> AUTO/%s (%s)",
            source.upper(), device["name"], device["ip"], target, auto_state_name,
        )
    else:
        log.warning(
            "%s: %s (%s) -> %s",
            source.upper(), device["name"], device["ip"], target,
        )
    return requested
