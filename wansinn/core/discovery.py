from __future__ import annotations

import logging
import re
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone

from .db import get_db
from .validation import validate_mac, validate_private_ipv4

log = logging.getLogger(__name__)
_discovery_lock = threading.Lock()


def _local_host_ipv4s() -> set[str]:
    """Return IPv4 addresses assigned to the WANSINN host.

    Discovery must never offer WANSINN's own interfaces as manageable devices.
    Linux `ip -o -4 addr show` is preferred because it includes all configured
    interfaces, not only the address selected by hostname resolution.
    """
    addresses: set[str] = set()
    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                for index, part in enumerate(parts):
                    if part == "inet" and index + 1 < len(parts):
                        candidate = parts[index + 1].split("/", 1)[0].strip()
                        try:
                            addresses.add(validate_private_ipv4(candidate))
                        except ValueError:
                            pass
    except (OSError, subprocess.TimeoutExpired):
        log.exception("DISCOVERY: lokale Host-IPs konnten nicht gelesen werden")

    # Loopback is not useful as a client either, even though validation rejects
    # it in normal device discovery.
    addresses.discard("127.0.0.1")
    return addresses


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _reserved_device_ips(app) -> set[str]:
    """IPs that WANSINN must never treat as manageable client devices."""
    reserved = set()

    for key in ("WANSINN_MANAGEMENT_IP", "WANSINN_TESTING_IP"):
        value = str(app.config.get(key, "")).strip()
        if not value:
            continue
        try:
            reserved.add(validate_private_ipv4(value))
        except ValueError:
            log.warning("DISCOVERY: ungültige reservierte IP in %s: %s", key, value)

    # Structured infrastructure list.
    try:
        rows = get_db().execute(
            "SELECT ip FROM infrastructure_addresses ORDER BY ip"
        ).fetchall()
        for row in rows:
            try:
                reserved.add(validate_private_ipv4(row["ip"]))
            except ValueError:
                log.warning(
                    "DISCOVERY: ungültige Infrastruktur-IP in Datenbank ignoriert: %s",
                    row["ip"],
                )
    except sqlite3.OperationalError:
        # During very early migration/startup the table may not exist yet.
        # Fall back to the legacy environment value for compatibility.
        custom = str(app.config.get("WANSINN_INFRASTRUCTURE_IPS", "")).strip()
        if custom:
            for raw in re.split(r"[\s,;]+", custom):
                value = raw.strip()
                if not value:
                    continue
                try:
                    reserved.add(validate_private_ipv4(value))
                except ValueError:
                    pass

    return reserved


def ingest_router_policies(app) -> dict[str, int]:
    """Adopt unambiguous router-side policies as fixed WANSINN devices."""
    addon = app.extensions.get("wansinn_addon")
    if addon is None or not hasattr(addon, "router_device_policies"):
        return {"imported": 0, "conflicts": 0}

    db = get_db()
    policies = addon.router_device_policies()
    reserved_ips = _reserved_device_ips(app)
    stats = {"imported": 0, "conflicts": 0}

    # A previously imported sensor/management IP is stale infrastructure state,
    # not a real managed client. Remove it deterministically.
    if reserved_ips:
        placeholders = ",".join("?" for _ in reserved_ips)
        removed = db.execute(
            f"DELETE FROM devices WHERE ip IN ({placeholders})",
            tuple(sorted(reserved_ips)),
        ).rowcount
        db.execute(
            f"DELETE FROM discovered_devices WHERE ip IN ({placeholders})",
            tuple(sorted(reserved_ips)),
        )
        db.commit()
        if removed:
            log.warning(
                "ROUTER IMPORT: %s reservierte WANSINN-Infrastruktur-Gerät(e) entfernt",
                removed,
            )

    for ip, profile in sorted(policies.items()):
        if ip in reserved_ips:
            log.info(
                "ROUTER IMPORT: %s ignoriert — reservierte WANSINN-Infrastruktur-IP",
                ip,
            )
            continue
        if profile is None:
            stats["conflicts"] += 1
            continue

        existing = db.execute(
            "SELECT id FROM devices WHERE ip=?",
            (ip,),
        ).fetchone()
        if existing is not None:
            continue

        # Re-use discovery knowledge when available so the imported row starts
        # with a useful identity instead of only an address.
        candidate = db.execute(
            """
            SELECT mac,name,last_seen
            FROM discovered_devices
            WHERE ip=?
            ORDER BY last_seen DESC
            LIMIT 1
            """,
            (ip,),
        ).fetchone()

        mac = candidate["mac"] if candidate is not None else None
        name = (
            candidate["name"].strip()
            if candidate is not None and candidate["name"].strip()
            else f"Router {ip}"
        )
        last_seen = candidate["last_seen"] if candidate is not None else ""

        # A discovered MAC may already belong to a managed device whose IP has
        # changed; don't create a duplicate identity in that case.
        if mac:
            mac_owner = db.execute(
                "SELECT id,name FROM devices WHERE mac=?",
                (mac,),
            ).fetchone()
            if mac_owner is not None:
                log.warning(
                    "ROUTER IMPORT: %s -> %s nicht importiert; MAC gehört bereits %s",
                    ip, profile, mac_owner["name"],
                )
                continue

        try:
            db.execute(
                """
                INSERT INTO devices(
                    name,ip,mac,note,wan_profile,effective_profile,last_seen,router_imported
                )
                VALUES(?,?,?,?,?,?,?,1)
                """,
                (
                    name[:80],
                    ip,
                    mac,
                    "Vom Router übernommen",
                    profile,
                    profile,
                    last_seen,
                ),
            )
            db.execute("DELETE FROM discovered_devices WHERE ip=?", (ip,))
            db.commit()
            stats["imported"] += 1
            log.warning(
                "ROUTER IMPORT: %s als festes Gerät übernommen -> %s",
                ip, profile,
            )
        except sqlite3.IntegrityError:
            db.rollback()
            log.exception("ROUTER IMPORT: %s konnte nicht übernommen werden", ip)

    return stats


def scan_devices(app) -> dict[str, int]:
    addon = app.extensions.get("wansinn_addon")
    if addon is None or not hasattr(addon, "discover_devices"):
        return {"seen": 0, "new": 0, "moved": 0, "bound": 0}

    reserved_ips = _reserved_device_ips(app)

    with _discovery_lock:
        found = addon.discover_devices()
        db = get_db()

        # Infrastructure endpoints are not manageable client devices.
        # Exclude every configured WAN gateway dynamically rather than
        # hard-coding addresses, so this also works for future/custom WANs.
        gateway_ips = {
            row["gateway"]
            for row in db.execute(
                "SELECT gateway FROM route_profiles WHERE gateway<>''"
            ).fetchall()
            if row["gateway"]
        }

        addon_infrastructure = set()
        if hasattr(addon, "discovery_infrastructure_ips"):
            try:
                addon_infrastructure = set(addon.discovery_infrastructure_ips())
            except Exception:
                log.exception("DISCOVERY: Infrastruktur-IP-Erkennung des Add-ons fehlgeschlagen")

        local_host_ips = _local_host_ipv4s()

        ignored_ips = {
            ip
            for ip in (
                reserved_ips
                | gateway_ips
                | addon_infrastructure
                | local_host_ips
            )
            if ip
        }

        log.info(
            "DISCOVERY: ignoriere Infrastruktur-IPs: %s",
            ", ".join(sorted(ignored_ips)) if ignored_ips else "keine",
        )
        if local_host_ips:
            log.info(
                "DISCOVERY: lokale WANSINN-Host-IPs: %s",
                ", ".join(sorted(local_host_ips)),
            )
        stats = {"seen": 0, "new": 0, "moved": 0, "bound": 0}

        # Clean stale infrastructure rows from both discovery and the managed
        # device list. The setup-defined sensor/management IPs are reserved and
        # must never become user-manageable devices.
        if ignored_ips:
            placeholders = ",".join("?" for _ in ignored_ips)
            db.execute(
                f"DELETE FROM discovered_devices WHERE ip IN ({placeholders})",
                tuple(sorted(ignored_ips)),
            )

            if reserved_ips:
                reserved_placeholders = ",".join("?" for _ in reserved_ips)
                removed = db.execute(
                    f"DELETE FROM devices WHERE ip IN ({reserved_placeholders})",
                    tuple(sorted(reserved_ips)),
                ).rowcount
                if removed:
                    log.warning(
                        "DISCOVERY: %s reservierte WANSINN-Infrastruktur-Gerät(e) entfernt",
                        removed,
                    )

            db.commit()

        for item in found:
            try:
                mac = validate_mac(item.get("mac", ""))
                ip = validate_private_ipv4(item.get("ip", ""))
            except ValueError:
                continue
            if ip in ignored_ips:
                log.info(
                    "DISCOVERY: ignoriere %s (%s) — Infrastruktur-IP",
                    ip, mac,
                )
                # Remove stale candidate immediately, even if it came from an
                # older build before this address was recognized as infrastructure.
                db.execute("DELETE FROM discovered_devices WHERE mac=? OR ip=?", (mac, ip))
                db.commit()
                continue

            stats["seen"] += 1
            name = str(item.get("name", "")).strip()[:80]
            source = str(item.get("source", "")).strip()[:40]
            interface = str(item.get("interface", "")).strip()[:80]

            managed = db.execute(
                "SELECT * FROM devices WHERE mac=?",
                (mac,),
            ).fetchone()

            if managed is None:
                # Safe adoption for older WANSINN installs: if an existing
                # managed device has exactly this IP and no MAC yet, bind it.
                legacy = db.execute(
                    "SELECT * FROM devices WHERE ip=? AND (mac IS NULL OR mac='')",
                    (ip,),
                ).fetchone()
                if legacy is not None:
                    try:
                        db.execute(
                            "UPDATE devices SET mac=?,last_seen=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                            (mac, _now(), legacy["id"]),
                        )
                        db.commit()
                        stats["bound"] += 1
                        log.warning(
                            "DISCOVERY: %s (%s) an bestehendes Gerät %s gebunden",
                            mac, ip, legacy["name"],
                        )
                    except sqlite3.IntegrityError:
                        db.rollback()
                    continue

                existing_candidate = db.execute(
                    "SELECT mac FROM discovered_devices WHERE mac=?",
                    (mac,),
                ).fetchone()
                db.execute(
                    """
                    INSERT INTO discovered_devices(mac,ip,name,source,interface,last_seen)
                    VALUES(?,?,?,?,?,?)
                    ON CONFLICT(mac) DO UPDATE SET
                        ip=excluded.ip,
                        name=CASE WHEN excluded.name<>'' THEN excluded.name ELSE discovered_devices.name END,
                        source=excluded.source,
                        interface=excluded.interface,
                        last_seen=excluded.last_seen
                    """,
                    (mac, ip, name, source, interface, _now()),
                )
                db.commit()
                if existing_candidate is None:
                    stats["new"] += 1
                continue

            # Managed MAC found: keep its current IP synchronized.
            if managed["ip"] != ip:
                conflict = db.execute(
                    "SELECT id,name,mac FROM devices WHERE ip=? AND id<>?",
                    (ip, managed["id"]),
                ).fetchone()
                if conflict is not None:
                    log.error(
                        "DISCOVERY: %s zog auf %s, aber IP gehört bereits %s",
                        managed["name"], ip, conflict["name"],
                    )
                    continue

                old_ip = managed["ip"]
                target = managed["effective_profile"] or managed["wan_profile"]

                try:
                    # Remove old source policy before assigning the new address.
                    addon.set_device_profile(old_ip, "auto")
                    addon.set_device_profile(ip, target)
                    db.execute(
                        """
                        UPDATE devices
                        SET ip=?,last_seen=?,updated_at=CURRENT_TIMESTAMP
                        WHERE id=?
                        """,
                        (ip, _now(), managed["id"]),
                    )
                    db.commit()
                    stats["moved"] += 1
                    log.warning(
                        "DISCOVERY: %s %s -> %s (MAC %s, Policy %s gehalten)",
                        managed["name"], old_ip, ip, mac, target,
                    )
                except Exception:
                    db.rollback()
                    log.exception(
                        "DISCOVERY: IP-Wechsel für %s (%s -> %s) fehlgeschlagen",
                        managed["name"], old_ip, ip,
                    )
            else:
                db.execute(
                    "UPDATE devices SET last_seen=? WHERE id=?",
                    (_now(), managed["id"]),
                )
                db.commit()

            # A managed MAC must not remain in the suggestion list.
            db.execute("DELETE FROM discovered_devices WHERE mac=?", (mac,))
            db.commit()

        policy_stats = ingest_router_policies(app)
        if policy_stats["imported"] or policy_stats["conflicts"]:
            log.warning(
                "ROUTER IMPORT: imported=%s conflicts=%s",
                policy_stats["imported"], policy_stats["conflicts"],
            )

        log.warning(
            "DISCOVERY scan: seen=%s new=%s bound=%s moved=%s ignored=%s",
            stats["seen"], stats["new"], stats["bound"], stats["moved"],
            len(ignored_ips),
        )
        return stats


def start_discovery_watcher(app) -> None:
    if app.extensions.get("wansinn_discovery_thread"):
        return

    def worker():
        # Give startup/setup a moment before first router query.
        time.sleep(8)
        while True:
            try:
                with app.app_context():
                    if app.config.get("WANSINN_CONFIGURED"):
                        stats = scan_devices(app)
                        if stats["new"] or stats["moved"] or stats["bound"]:
                            log.warning(
                                "DISCOVERY: seen=%s new=%s bound=%s moved=%s",
                                stats["seen"], stats["new"], stats["bound"], stats["moved"],
                            )
            except Exception:
                log.exception("WANSINN Device Discovery")
            time.sleep(30)

    thread = threading.Thread(
        target=worker,
        name="wansinn-device-discovery",
        daemon=True,
    )
    app.extensions["wansinn_discovery_thread"] = thread
    thread.start()
