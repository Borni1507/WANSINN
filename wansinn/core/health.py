from __future__ import annotations
import ipaddress, logging, shutil, sqlite3, subprocess, threading, time
from datetime import datetime, timezone
from .db import get_db
from .i18n import t
from .networking import provision_testing_ip

log=logging.getLogger(__name__)
_probe_lock=threading.Lock()
_reconcile_lock=threading.Lock()
_trace_lock=threading.Lock()
_trace_last_run={}
_TRACE_MIN_INTERVAL=60

def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _availability_key(statuses):
    return ",".join(f"{p}={'1' if statuses[p] else '0'}" for p in sorted(statuses))

def _health_availability(db):
    rows=db.execute("SELECT profile_id,health_status FROM route_profiles WHERE enabled=1 ORDER BY profile_id").fetchall()
    return {r["profile_id"]: r["health_status"]=="up" for r in rows}

class _TestingIPUnavailable(RuntimeError):
    pass


def _trace_line_has_ip(line, address):
    """Return True only when a numbered traceroute hop contains ``address``."""
    parts=line.strip().split()
    if len(parts) < 2 or not parts[0].isdigit():
        return False
    try:
        wanted=ipaddress.ip_address(address)
    except ValueError:
        wanted=None
    for token in parts[1:]:
        candidate=token.strip("()[],:;")
        try:
            if wanted is not None and ipaddress.ip_address(candidate) == wanted:
                return True
        except ValueError:
            continue
        if wanted is None and candidate == address:
            return True
    return False


def _trace_line_reaches_target(line, target):
    """Return True only when a traceroute hop line actually contains target.

    The traceroute header also contains the destination, so a plain substring
    search would create false positives. Only numbered hop lines count.
    """
    return _trace_line_has_ip(line, target)


def _local_trace_probe(testing_ip, target, timeout, profile_id, expected_gateway):
    """Use traceroute itself as the authoritative WAN health probe.

    A probe is usable only when the configured gateway appears as an actual
    traceroute hop. This rejects transient cross-WAN routing leaks without
    turning them into false UP/DOWN samples. A valid probe is healthy only
    when the configured target is reached. Every trace is kept in DEBUG.
    """
    traceroute=shutil.which("traceroute")
    if not traceroute:
        raise RuntimeError(
            "traceroute fehlt. Bitte das Paket 'traceroute' installieren."
        )

    # Traceroute health is intentionally deterministic; the old Ping-Timeout UI no longer controls it.
    wait=1
    command=[
        traceroute, "-n", "-I", "-s", testing_ip,
        "-q", "1", "-w", str(wait), "-m", "16", target,
    ]
    log.debug(
        "HEALTH/TRACE: begin profile=%s testing_ip=%s target=%s",
        profile_id, testing_ip, target,
    )
    try:
        result=subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=(16 * wait) + 4,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout=exc.stdout or ""
        stderr=exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout=stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr=stderr.decode(errors="replace")
        for line in str(stdout).splitlines():
            log.debug("HEALTH/TRACE: profile=%s %s", profile_id, line.rstrip())
        for line in str(stderr).splitlines():
            log.debug("HEALTH/TRACE: profile=%s stderr=%s", profile_id, line.rstrip())
        lines=str(stdout).splitlines()
        reached=any(_trace_line_reaches_target(line, target) for line in lines)
        gateway_seen=any(_trace_line_has_ip(line, expected_gateway) for line in lines)
        log.debug(
            "HEALTH/TRACE: timeout profile=%s target=%s reached=%s gateway_seen=%s",
            profile_id, target, reached, gateway_seen,
        )
        return reached, gateway_seen

    output=result.stdout or ""
    error=result.stderr or ""
    detail=f"{error}\n{output}".lower()
    if (
        "not enough privileges" in detail
        or "operation not permitted" in detail
        or "vorgang nicht zulässig" in detail
        or "permission denied" in detail
    ):
        raise RuntimeError(
            "Traceroute hat nicht genügend Netzwerkrechte. "
            "Bitte ./install.sh erneut ausführen, damit CAP_NET_RAW gesetzt wird."
        )
    if (
        "cannot assign requested address" in detail
        or ("bind" in detail and "address" in detail)
    ):
        raise _TestingIPUnavailable(
            f"Testing-IP {testing_ip} ist lokal nicht verfügbar."
        )

    reached=False
    gateway_seen=False
    for line in output.splitlines():
        log.debug("HEALTH/TRACE: profile=%s %s", profile_id, line.rstrip())
        if _trace_line_reaches_target(line, target):
            reached=True
        if _trace_line_has_ip(line, expected_gateway):
            gateway_seen=True
    for line in error.splitlines():
        log.debug("HEALTH/TRACE: profile=%s stderr=%s", profile_id, line.rstrip())

    log.debug(
        "HEALTH/TRACE: end profile=%s target=%s rc=%s reached=%s gateway=%s gateway_seen=%s",
        profile_id, target, result.returncode, reached, expected_gateway, gateway_seen,
    )
    return reached, gateway_seen

def _addon_has_capability(addon, capability):
    info = getattr(addon, "info", None)
    return bool(info and capability in getattr(info, "capabilities", ()))


def _probe_addon_profile(addon, profile_id, target, timeout):
    """Run an add-on owned, route-scoped provider probe."""
    probe = getattr(addon, "probe_profile", None)
    if not callable(probe):
        raise RuntimeError("Add-on bietet keinen Profil-Probe an.")
    return bool(probe(profile_id, target, timeout))


def _probe_provider(app,addon,profile_id,target,timeout,expected_gateway):
    testing_ip=app.config.get("WANSINN_TESTING_IP","").strip()
    if not testing_ip:
        raise RuntimeError("Testing-IP ist nicht konfiguriert.")
    expected_gateway=str(expected_gateway or "").strip()
    if not expected_gateway:
        raise RuntimeError(f"Gateway für Profil {profile_id} ist nicht konfiguriert.")
    log.info(
        "HEALTH/PROBE: begin profile=%s testing_ip=%s target=%s timeout=%ss",
        profile_id, testing_ip, target, timeout,
    )
    with _probe_lock:
        log.info("HEALTH/PROBE: set %s -> %s", testing_ip, profile_id)
        addon.set_device_profile(testing_ip,profile_id)
        try:
            try:
                ok, path_valid = _local_trace_probe(
                    testing_ip,target,timeout,profile_id,expected_gateway
                )
            except _TestingIPUnavailable:
                management_ip = str(
                    app.config.get("WANSINN_MANAGEMENT_IP", "")
                ).strip()
                if not management_ip:
                    raise RuntimeError(
                        "Testing-IP fehlt lokal und Management-IP ist nicht konfiguriert."
                    )
                log.warning(
                    "HEALTH/PROBE: Testing-IP %s disappeared; restoring before retry",
                    testing_ip,
                )
                state = provision_testing_ip(management_ip, testing_ip)
                log.warning(
                    "HEALTH/PROBE: Testing-IP %s restored on %s/%s",
                    testing_ip,
                    state.get("interface", "?"),
                    state.get("prefixlen", "?"),
                )
                ok, path_valid = _local_trace_probe(
                    testing_ip,target,timeout,profile_id,expected_gateway
                )
            if not path_valid:
                log.warning(
                    "HEALTH/PROBE: discard profile=%s testing_ip=%s target=%s "
                    "reason=wrong-path expected_gateway=%s; retrying",
                    profile_id, testing_ip, target, expected_gateway,
                )
                time.sleep(0.5)
                ok, path_valid = _local_trace_probe(
                    testing_ip,target,timeout,profile_id,expected_gateway
                )
                if not path_valid:
                    log.warning(
                        "HEALTH/PROBE: result profile=%s testing_ip=%s target=%s "
                        "valid=False reason=wrong-path expected_gateway=%s",
                        profile_id, testing_ip, target, expected_gateway,
                    )
                    return None
            log.info(
                "HEALTH/PROBE: result profile=%s testing_ip=%s target=%s "
                "reachable=%s valid=True gateway=%s",
                profile_id, testing_ip, target, ok, expected_gateway,
            )
            return ok
        finally:
            try:
                addon.set_device_profile(testing_ip,"auto")
                log.info("HEALTH/PROBE: reset %s -> auto", testing_ip)
            except Exception:
                log.exception("Testing-IP %s konnte nicht auf AUTO zurückgesetzt werden",testing_ip)

def _commit_with_retry(db, attempts=6):
    """Commit short SQLite writes without turning a transient writer lock into a failed reconcile."""
    delay=0.05
    for attempt in range(attempts):
        try:
            db.commit()
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt==attempts-1:
                raise
            time.sleep(delay)
            delay=min(delay*2,0.8)


def _update_effective_profile(db,device_id,target):
    delay=0.05
    for attempt in range(6):
        try:
            db.execute(
                "UPDATE devices SET effective_profile=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (target,device_id),
            )
            _commit_with_retry(db)
            return
        except sqlite3.OperationalError as exc:
            db.rollback()
            if "locked" not in str(exc).lower() or attempt==5:
                raise
            time.sleep(delay)
            delay=min(delay*2,0.8)


def rehydrate_router_state(app, db):
    """Re-apply WANSINN's desired runtime state after router/app restart."""
    addon=app.extensions.get("wansinn_addon")
    if addon is None:
        return
    devices=db.execute(
        "SELECT id,name,ip,wan_profile,effective_profile,automation_override FROM devices ORDER BY id"
    ).fetchall()
    for d in devices:
        if d["automation_override"] == "offline":
            target="offline"
        elif d["wan_profile"] == "auto":
            target=(d["effective_profile"] or "").strip()
        else:
            target=(d["wan_profile"] or "").strip()
        if not target or target == "auto":
            continue
        try:
            addon.apply_effective_profile(d["ip"], target)
            log.warning("REHYDRATE/WANSINN: %s (%s) -> %s", d["name"], d["ip"], target)
        except Exception:
            log.exception("Routerzustand für %s konnte nicht auf %s wiederhergestellt werden", d["name"], target)

def rearm_recovered_profiles(app, db, recovered_profiles):
    """Re-apply already selected profiles after an uplink recovers.

    OpenWrt/netifd may remove a WANSINN policy-table default route while an
    uplink is down. The fail-closed backend deliberately leaves an ``unreachable default``
    behind so the client fails closed instead of falling through to ``main``.
    When that same uplink comes back, the admin's desired state has *not*
    changed, so rebuild the runtime route for devices that are still assigned
    to the recovered profile. This is a re-arm, not a failover decision.
    """
    addon = app.extensions.get("wansinn_addon")
    if addon is None:
        return

    recovered = {str(p).strip() for p in recovered_profiles if str(p).strip()}
    if not recovered:
        return

    placeholders = ",".join("?" for _ in recovered)
    params = tuple(sorted(recovered))
    devices = db.execute(
        f"""
        SELECT id,name,ip,wan_profile,effective_profile,automation_override
        FROM devices
        WHERE wan_profile IN ({placeholders})
        ORDER BY id
        """,
        params,
    ).fetchall()

    for d in devices:
        if d["automation_override"] == "offline":
            continue
        target = d["wan_profile"]
        if target not in recovered or target in {"auto", "offline", ""}:
            continue
        try:
            addon.apply_effective_profile(d["ip"], target)
            log.warning("REARM/WANSINN: %s (%s) -> %s", d["name"], d["ip"], target)
        except Exception:
            log.exception("REARM konnte %s nicht erneut auf %s setzen", d["name"], target)


def reconcile_auto_state(app,db):
    # Only one AUTO reconcile may manipulate device policies at a time.
    # Health checks and web requests can otherwise race during large failovers.
    with _reconcile_lock:
        addon=app.extensions.get("wansinn_addon")
        if addon is None: return
        availability=_health_availability(db)
        if not availability: return
        key=_availability_key(availability)
        state=db.execute("SELECT id,name FROM auto_states WHERE availability_key=?",(key,)).fetchone()
        if state is None: return
        mapping={r["device_id"]:r["profile_id"] for r in db.execute(
            "SELECT device_id,profile_id FROM auto_state_device_routes WHERE state_id=?",(state["id"],)
        ).fetchall()}
        devices=db.execute(
            "SELECT id,name,ip,effective_profile,automation_override "
            "FROM devices WHERE wan_profile='auto'"
        ).fetchall()
        for d in devices:
            if d["automation_override"] == "offline":
                continue
            target=mapping.get(d["id"])
            if not target or d["effective_profile"]==target:
                continue
            if target!="offline" and not availability.get(target,False):
                continue
            try:
                # Router operation first; no SQLite write transaction is held
                # while SSH/API work is in progress.
                addon.apply_effective_profile(d["ip"],target)
                _update_effective_profile(db,d["id"],target)
                log.warning("AUTO: %s -> %s (%s)",d["name"],target,state["name"])
            except Exception:
                log.exception("AUTO konnte %s nicht auf %s setzen",d["name"],target)

def _probe_once(app):
    addon=app.extensions.get("wansinn_addon")
    if addon is None:
        log.warning("HEALTH/WATCHER: probe skipped because no add-on is loaded")
        return
    db=get_db()
    now_mono=time.monotonic()
    runtime=app.extensions.setdefault("wansinn_health_runtime",{"last_probe":{},"router_state_hydrated":False})
    ensure_control=getattr(addon,"ensure_control",None)
    if callable(ensure_control):
        try:
            status=ensure_control()
        except Exception:
            log.exception("Router-Exclusive-Control konnte nicht hergestellt werden")
            runtime["router_state_hydrated"]=False
            return
        if not status.get("exclusive", False):
            runtime["router_state_hydrated"]=False
            return
        if not runtime.get("router_state_hydrated",False):
            rehydrate_router_state(app,db)
            runtime["router_state_hydrated"]=True
    last_probe=runtime["last_probe"]
    profiles=db.execute(
        "SELECT profile_id,gateway,health_target,health_interval,health_timeout,"
        "fail_threshold,recover_threshold,health_status,health_fail_count,health_ok_count "
        "FROM route_profiles WHERE enabled=1 AND managed=1 ORDER BY profile_id"
    ).fetchall()
    runtime["last_profile_count"] = len(profiles)
    availability_changed=False
    recovered_profiles=[]

    readonly_status = None
    has_router_probe = _addon_has_capability(addon, "router-profile-probe")
    if (
        not has_router_probe
        and not _addon_has_capability(addon, "device-policy-routing")
        and hasattr(addon, "profile_availability")
    ):
        try:
            readonly_status = addon.profile_availability()
        except Exception:
            log.exception("Read-only WAN-Status konnte nicht gelesen werden")

    for p in profiles:
        pid=p["profile_id"]
        interval=max(2,min(int(p["health_interval"]),300))
        age = now_mono-last_probe.get(pid,0.0)
        if age<interval:
            continue
        last_probe[pid]=now_mono
        log.info(
            "HEALTH/WATCHER: probing profile=%s status=%s interval=%ss target=%s",
            pid, p["health_status"], interval, p["health_target"],
        )
        try:
            if has_router_probe:
                ok=_probe_addon_profile(
                    addon,pid,p["health_target"],p["health_timeout"]
                )
            elif readonly_status is not None and pid in readonly_status:
                ok=bool(readonly_status[pid])
            else:
                ok=_probe_provider(
                    app,addon,pid,p["health_target"],p["health_timeout"],p["gateway"]
                )
        except Exception:
            log.exception("WAN-Healthcheck %s technisch fehlgeschlagen",pid)
            db.execute("UPDATE route_profiles SET health_status='unknown',health_last_check=? WHERE profile_id=?",(_now(),pid))
            db.commit()
            continue
        if ok is None:
            log.warning(
                "HEALTH/WATCHER: ignored invalid probe profile=%s; "
                "health state and counters unchanged",
                pid,
            )
            continue
        old=p["health_status"]
        fail_count=int(p["health_fail_count"]); ok_count=int(p["health_ok_count"])
        if ok:
            ok_count+=1; fail_count=0; new=old
            if old in {"down","unknown"} and ok_count>=int(p["recover_threshold"]): new="up"
        else:
            fail_count+=1; ok_count=0; new=old
            if old in {"up","unknown"} and fail_count>=int(p["fail_threshold"]): new="down"
        changed=new!=old
        db.execute(
            "UPDATE route_profiles SET health_status=?,health_fail_count=?,health_ok_count=?,"
            "health_last_check=?,health_last_change=CASE WHEN ? THEN ? ELSE health_last_change END "
            "WHERE profile_id=?",
            (new,fail_count,ok_count,_now(),int(changed),_now(),pid)
        )
        db.commit()
        if changed:
            availability_changed=True
            if old == "down" and new == "up":
                recovered_profiles.append(pid)
            log.warning("WAN %s: %s -> %s",pid,old,new)
    if availability_changed:
        # AUTO needs a concrete effective profile on the router at all times.
        # GL.iNet advertises the narrower auto-device-policy-routing contract:
        # WANSINN owns AUTO decisions while the add-on applies only the resolved
        # WAN/OFFLINE target through its fail-closed runtime PBR layer.
        if (
            _addon_has_capability(addon, "device-policy-routing")
            or _addon_has_capability(addon, "auto-device-policy-routing")
        ):
            reconcile_auto_state(app,db)

        # Re-arming an already selected profile is not an AUTO decision.
        # Manual OpenWrt routing needs this too: netifd can remove the live
        # default route from the WANSINN policy table while a WAN is down.
        # When that same WAN recovers, re-apply the existing desired profile.
        if recovered_profiles and (
            _addon_has_capability(addon, "device-policy-routing")
            or _addon_has_capability(addon, "manual-device-policy-routing")
            or _addon_has_capability(addon, "fail-closed-device-policy-routing")
        ):
            rearm_recovered_profiles(app, db, recovered_profiles)

def start_health_watcher(app):
    if app.extensions.get("wansinn_health_thread"):
        log.warning("HEALTH/WATCHER: start requested but thread is already registered")
        return

    log.info(
        "HEALTH/WATCHER: starting configured=%s addon=%s testing_ip=%s",
        app.config.get("WANSINN_CONFIGURED"),
        app.config.get("WANSINN_ADDON") or "<none>",
        app.config.get("WANSINN_TESTING_IP") or "<none>",
    )

    def worker():
        log.info("HEALTH/WATCHER: worker thread entered")
        last_heartbeat=0.0
        while True:
            try:
                with app.app_context():
                    now=time.monotonic()
                    configured=bool(app.config.get("WANSINN_CONFIGURED"))
                    if now-last_heartbeat>=30:
                        runtime=app.extensions.get("wansinn_health_runtime") or {}
                        thread=threading.current_thread()
                        log.info(
                            "HEALTH/WATCHER: heartbeat alive=%s configured=%s addon_loaded=%s profiles_last_seen=%s",
                            thread.is_alive(), configured,
                            app.extensions.get("wansinn_addon") is not None,
                            runtime.get("last_profile_count", "?"),
                        )
                        last_heartbeat=now
                    if configured:
                        _probe_once(app)
            except Exception:
                log.exception("WANSINN WAN-Health-Watcher")
            time.sleep(1)
    t=threading.Thread(target=worker,name="wansinn-wan-health",daemon=True)
    app.extensions["wansinn_health_thread"]=t
    t.start()
    log.info("HEALTH/WATCHER: thread started ident=%s", t.ident)
