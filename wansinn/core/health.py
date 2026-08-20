from __future__ import annotations
import logging, sqlite3, subprocess, threading, time
from datetime import datetime, timezone
from .db import get_db
from .i18n import t

log=logging.getLogger(__name__)
_probe_lock=threading.Lock()
_reconcile_lock=threading.Lock()

def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _availability_key(statuses):
    return ",".join(f"{p}={'1' if statuses[p] else '0'}" for p in sorted(statuses))

def _health_availability(db):
    rows=db.execute("SELECT profile_id,health_status FROM route_profiles WHERE enabled=1 ORDER BY profile_id").fetchall()
    return {r["profile_id"]: r["health_status"]=="up" for r in rows}

def _local_ping(testing_ip,target,timeout):
    timeout=max(1,min(int(timeout),10))
    result=subprocess.run(
        ["ping","-I",testing_ip,"-c","1","-W",str(timeout),target],
        capture_output=True,text=True,timeout=timeout+2,check=False,
    )
    return result.returncode==0

def _addon_has_capability(addon, capability):
    info = getattr(addon, "info", None)
    return bool(info and capability in getattr(info, "capabilities", ()))


def _probe_addon_profile(addon, profile_id, target, timeout):
    """Run an add-on owned, route-scoped provider probe."""
    probe = getattr(addon, "probe_profile", None)
    if not callable(probe):
        raise RuntimeError("Add-on bietet keinen Profil-Probe an.")
    return bool(probe(profile_id, target, timeout))


def _probe_provider(app,addon,profile_id,target,timeout):
    testing_ip=app.config.get("WANSINN_TESTING_IP","").strip()
    if not testing_ip:
        raise RuntimeError("Testing-IP ist nicht konfiguriert.")
    with _probe_lock:
        addon.set_device_profile(testing_ip,profile_id)
        try:
            return _local_ping(testing_ip,target,timeout)
        finally:
            try:
                addon.set_device_profile(testing_ip,"auto")
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
    if addon is None: return
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
        "SELECT profile_id,health_target,health_interval,health_timeout,"
        "fail_threshold,recover_threshold,health_status,health_fail_count,health_ok_count "
        "FROM route_profiles WHERE enabled=1 AND managed=1 ORDER BY profile_id"
    ).fetchall()
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
        if now_mono-last_probe.get(pid,0.0)<interval:
            continue
        last_probe[pid]=now_mono
        try:
            if has_router_probe:
                ok=_probe_addon_profile(
                    addon,pid,p["health_target"],p["health_timeout"]
                )
            elif readonly_status is not None and pid in readonly_status:
                ok=bool(readonly_status[pid])
            else:
                ok=_probe_provider(app,addon,pid,p["health_target"],p["health_timeout"])
        except Exception:
            log.exception("WAN-Healthcheck %s technisch fehlgeschlagen",pid)
            db.execute("UPDATE route_profiles SET health_status='unknown',health_last_check=? WHERE profile_id=?",(_now(),pid))
            db.commit()
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
    if app.extensions.get("wansinn_health_thread"): return
    def worker():
        while True:
            try:
                with app.app_context():
                    if app.config.get("WANSINN_CONFIGURED"):
                        _probe_once(app)
            except Exception:
                log.exception("WANSINN WAN-Health-Watcher")
            time.sleep(1)
    t=threading.Thread(target=worker,name="wansinn-wan-health",daemon=True)
    app.extensions["wansinn_health_thread"]=t
    t.start()
