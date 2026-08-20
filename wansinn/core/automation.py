from __future__ import annotations
import logging
import threading
import time
from datetime import datetime
from .db import get_db
from .i18n import t

log = logging.getLogger(__name__)

def _restore_device(app, db, device):
    addon = app.extensions.get("wansinn_addon")
    if addon is None:
        raise RuntimeError("Router-Add-on ist nicht geladen.")

    base = device["wan_profile"]
    db.execute(
        "UPDATE devices SET automation_override='',automation_override_at='',"
        "updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (device["id"],),
    )
    db.commit()

    if base == "auto":
        db.execute(
            "UPDATE devices SET effective_profile='auto',updated_at=CURRENT_TIMESTAMP "
            "WHERE id=?",
            (device["id"],),
        )
        db.commit()
        from .health import reconcile_auto_state
        reconcile_auto_state(app, db)
    else:
        addon.set_device_profile(device["ip"], base)
        db.execute(
            "UPDATE devices SET effective_profile=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (base, device["id"]),
        )
        db.commit()

def execute_rule(app, db, rule, *, now=None):
    addon = app.extensions.get("wansinn_addon")
    if addon is None:
        raise RuntimeError("Router-Add-on ist nicht geladen.")

    device = db.execute(
        "SELECT id,name,ip,wan_profile,effective_profile,automation_override "
        "FROM devices WHERE id=?",
        (rule["device_id"],),
    ).fetchone()
    if device is None:
        raise RuntimeError("Gerät nicht gefunden.")

    stamp = (now or datetime.now()).isoformat(timespec="seconds")
    if rule["action"] == "offline":
        addon.set_device_profile(device["ip"], "offline")
        db.execute(
            "UPDATE devices SET automation_override='offline',automation_override_at=?,"
            "effective_profile='offline',updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (stamp, device["id"]),
        )
        db.commit()
        log.warning("SCHEDULE: %s (%s) -> OFFLINE", device["name"], device["ip"])
    elif rule["action"] == "online":
        _restore_device(app, db, device)
        restored = db.execute(
            "SELECT effective_profile FROM devices WHERE id=?",(device["id"],)
        ).fetchone()
        log.warning(
            "SCHEDULE: %s (%s) -> ONLINE / %s",
            device["name"], device["ip"],
            restored["effective_profile"] if restored else device["wan_profile"],
        )
    else:
        raise RuntimeError("Unbekannte Automation-Aktion.")


def _rule_week_minute(rule, day):
    hour, minute = (int(part) for part in rule["time_hhmm"].split(":", 1))
    return day * 1440 + hour * 60 + minute


def reconcile_device_automation_now(app, db, device_id, *, now=None):
    """Immediately align one device with its currently applicable schedule state.

    Used after schedule/window edits. The normal watcher still fires individual
    rules at their exact times; this function handles the UX case where an admin
    moves a window across the current time and expects the router state to match
    the saved schedule immediately.
    """
    now = now or datetime.now()
    device = db.execute(
        """
        SELECT id,name,ip,wan_profile,effective_profile,automation_override
        FROM devices WHERE id=?
        """,
        (device_id,),
    ).fetchone()
    if device is None:
        return None

    rules = db.execute(
        """
        SELECT id,device_id,action,time_hhmm,weekdays,last_fired_key
        FROM automation_rules
        WHERE device_id=? AND active=1
        ORDER BY id
        """,
        (device_id,),
    ).fetchall()

    if not rules:
        if device["automation_override"]:
            _restore_device(app, db, device)
            log.warning(
                "SCHEDULE RECONCILE: %s (%s) -> Basisprofil (keine aktive Regel)",
                device["name"], device["ip"],
            )
            return "online"
        return None

    current_week_minute = (
        now.weekday() * 1440 + now.hour * 60 + now.minute
    )
    candidates = []

    for rule in rules:
        for raw_day in rule["weekdays"].split(","):
            if raw_day == "":
                continue
            day = int(raw_day)
            event_minute = _rule_week_minute(rule, day)

            # Represent last week's occurrence as a negative distance when the
            # event has not happened yet this week. This makes the scheduler
            # cyclic across Sunday -> Monday.
            if event_minute <= current_week_minute:
                distance = current_week_minute - event_minute
            else:
                distance = current_week_minute + (7 * 1440 - event_minute)

            candidates.append((distance, -rule["id"], rule))

    if not candidates:
        return None

    _distance, _rule_order, applicable = min(
        candidates,
        key=lambda item: (item[0], item[1]),
    )
    action = applicable["action"]

    # Avoid needless SSH when the desired state is already effective.
    if action == "offline":
        if (
            device["automation_override"] == "offline"
            and device["effective_profile"] == "offline"
        ):
            return "offline"
    elif action == "online":
        if not device["automation_override"]:
            return "online"

    execute_rule(app, db, applicable, now=now)
    log.warning(
        "SCHEDULE RECONCILE: %s (%s) -> %s nach Konfigurationsänderung",
        device["name"],
        device["ip"],
        action.upper(),
    )
    return action


def _run_due_rules(app):
    now = datetime.now()
    weekday = str(now.weekday())
    hhmm = now.strftime("%H:%M")
    fire_key = now.strftime("%Y-%m-%dT%H:%M")
    db = get_db()
    rules = db.execute(
        "SELECT id,device_id,action,time_hhmm,weekdays,last_fired_key "
        "FROM automation_rules WHERE active=1 AND time_hhmm=? ORDER BY id",
        (hhmm,),
    ).fetchall()
    for rule in rules:
        days = {x for x in rule["weekdays"].split(",") if x}
        if weekday not in days or rule["last_fired_key"] == fire_key:
            continue
        try:
            execute_rule(app, db, rule, now=now)
            db.execute(
                "UPDATE automation_rules SET last_fired_key=?,updated_at=CURRENT_TIMESTAMP "
                "WHERE id=?",(fire_key,rule["id"])
            )
            db.commit()
        except Exception:
            db.rollback()
            log.exception("SCHEDULE: Regel %s fehlgeschlagen", rule["id"])

def start_automation_watcher(app):
    if app.extensions.get("wansinn_automation_thread"):
        return
    def worker():
        while True:
            try:
                with app.app_context():
                    if app.config.get("WANSINN_CONFIGURED"):
                        _run_due_rules(app)
            except Exception:
                log.exception("WANSINN Automation-Watcher")
            time.sleep(15)
    t=threading.Thread(target=worker,name="wansinn-automation",daemon=True)
    app.extensions["wansinn_automation_thread"]=t
    t.start()
