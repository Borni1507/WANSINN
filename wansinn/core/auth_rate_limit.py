from __future__ import annotations

import hashlib
import time

from flask import current_app, request

from .db import get_db

# Progressive cooldown after the fifth failed login. The final value is the
# maximum cooldown and is reused for all subsequent failures.
_COOLDOWNS = (30, 60, 120, 300, 900)
_FIRST_LIMITED_FAILURE = 5
_RESET_AFTER_SECONDS = 24 * 60 * 60


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def client_ip() -> str:
    """Return the login client's address without trusting proxy headers by default."""
    if current_app.config.get("WANSINN_TRUST_PROXY"):
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip()
    return request.remote_addr or "unknown"


def _keys(ip: str, username: str) -> tuple[tuple[str, str], tuple[str, str]]:
    normalized_user = username.strip().casefold()
    return (
        ("ip", _digest(ip)),
        ("pair", _digest(f"{ip}\0{normalized_user}")),
    )


def _load(scope: str, identity_hash: str, now: int) -> tuple[int, int]:
    db = get_db()
    row = db.execute(
        "SELECT failures,blocked_until,updated_at FROM login_rate_limits "
        "WHERE scope=? AND identity_hash=?",
        (scope, identity_hash),
    ).fetchone()
    if row is None:
        return 0, 0

    failures = int(row["failures"] or 0)
    blocked_until = int(row["blocked_until"] or 0)
    updated_at = int(row["updated_at"] or 0)

    # Old failed-login history should not punish a client forever. Active blocks
    # are preserved, but an idle record decays after one day.
    if blocked_until <= now and updated_at and now - updated_at >= _RESET_AFTER_SECONDS:
        db.execute(
            "DELETE FROM login_rate_limits WHERE scope=? AND identity_hash=?",
            (scope, identity_hash),
        )
        db.commit()
        return 0, 0
    return failures, blocked_until


def retry_after(ip: str, username: str, now: int | None = None) -> int:
    now = int(time.time()) if now is None else int(now)
    remaining = 0
    for scope, identity_hash in _keys(ip, username):
        _failures, blocked_until = _load(scope, identity_hash, now)
        remaining = max(remaining, blocked_until - now)
    return max(0, remaining)


def _cooldown_for_failure(failures: int) -> int:
    if failures < _FIRST_LIMITED_FAILURE:
        return 0
    index = min(failures - _FIRST_LIMITED_FAILURE, len(_COOLDOWNS) - 1)
    return _COOLDOWNS[index]


def record_failure(ip: str, username: str, now: int | None = None) -> int:
    now = int(time.time()) if now is None else int(now)
    db = get_db()
    max_cooldown = 0
    for scope, identity_hash in _keys(ip, username):
        failures, _blocked_until = _load(scope, identity_hash, now)
        failures += 1
        cooldown = _cooldown_for_failure(failures)
        blocked_until = now + cooldown if cooldown else 0
        max_cooldown = max(max_cooldown, cooldown)
        db.execute(
            "INSERT INTO login_rate_limits(scope,identity_hash,failures,blocked_until,updated_at) "
            "VALUES(?,?,?,?,?) "
            "ON CONFLICT(scope,identity_hash) DO UPDATE SET "
            "failures=excluded.failures,blocked_until=excluded.blocked_until,updated_at=excluded.updated_at",
            (scope, identity_hash, failures, blocked_until, now),
        )
    db.commit()
    return max_cooldown


def clear_success(ip: str, username: str) -> None:
    db = get_db()
    for scope, identity_hash in _keys(ip, username):
        db.execute(
            "DELETE FROM login_rate_limits WHERE scope=? AND identity_hash=?",
            (scope, identity_hash),
        )
    db.commit()


def prune_old(now: int | None = None) -> None:
    now = int(time.time()) if now is None else int(now)
    get_db().execute(
        "DELETE FROM login_rate_limits WHERE blocked_until <= ? AND updated_at < ?",
        (now, now - _RESET_AFTER_SECONDS),
    )
    get_db().commit()
