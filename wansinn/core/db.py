import sqlite3
from pathlib import Path
from flask import current_app, g


SCHEMA = '''
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip TEXT NOT NULL UNIQUE,
    wan_profile TEXT NOT NULL DEFAULT 'auto',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    effective_profile TEXT NOT NULL DEFAULT 'auto'
);


CREATE TABLE IF NOT EXISTS discovered_devices (
    mac TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    interface TEXT NOT NULL DEFAULT '',
    last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_rate_limits (
    scope TEXT NOT NULL CHECK (scope IN ('ip', 'pair')),
    identity_hash TEXT NOT NULL,
    failures INTEGER NOT NULL DEFAULT 0,
    blocked_until INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, identity_hash)
);

CREATE INDEX IF NOT EXISTS idx_login_rate_limits_updated
ON login_rate_limits(updated_at);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS infrastructure_addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE IF NOT EXISTS automation_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('online', 'offline')),
    start_hhmm TEXT NOT NULL,
    end_hhmm TEXT NOT NULL,
    weekdays TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6',
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS automation_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('offline', 'online')),
    time_hhmm TEXT NOT NULL,
    weekdays TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6',
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    last_fired_key TEXT NOT NULL DEFAULT '',
    window_id INTEGER,
    window_edge TEXT CHECK (window_edge IN ('start', 'end') OR window_edge IS NULL),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    FOREIGN KEY (window_id) REFERENCES automation_windows(id) ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS route_profiles (
    profile_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    color TEXT NOT NULL DEFAULT '#6f7d90',
    gateway TEXT NOT NULL DEFAULT '',
    managed INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auto_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    availability_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auto_state_device_routes (
    state_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    profile_id TEXT NOT NULL,
    PRIMARY KEY (state_id, device_id),
    FOREIGN KEY (state_id) REFERENCES auto_states(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);
'''


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=15.0)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
        g.db.execute("PRAGMA busy_timeout = 15000")
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _columns(db, table):
    return {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}


def _migrate_legacy_database():
    new_path = Path(current_app.config["DATABASE"])
    old_candidates = [Path(current_app.instance_path) / "rackcontrol.sqlite"]
    if new_path.exists():
        return
    for old_path in old_candidates:
        if old_path.exists():
            new_path.write_bytes(old_path.read_bytes())
            return


def _migrate_devices_table(db):
    tables = {
        row["name"]
        for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    if "devices" not in tables:
        return
    cols = _columns(db, "devices")
    if "wan_profile" in cols:
        return
    if "mode" not in cols:
        raise RuntimeError("Unbekannte ältere devices-Tabelle.")

    db.executescript('''
    ALTER TABLE devices RENAME TO devices_old;
    CREATE TABLE devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        ip TEXT NOT NULL UNIQUE,
        wan_profile TEXT NOT NULL DEFAULT 'auto',
        note TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    INSERT INTO devices (id, name, ip, wan_profile, note, created_at, updated_at)
    SELECT id, name, ip,
           CASE WHEN mode = 'vdsl' THEN 'telekom' ELSE 'auto' END,
           note, created_at, updated_at
    FROM devices_old;
    DROP TABLE devices_old;
    ''')


def _migrate_v1171(db):
    cols = _columns(db, "devices")
    if "effective_profile" not in cols:
        db.execute(
            "ALTER TABLE devices ADD COLUMN effective_profile TEXT NOT NULL DEFAULT 'auto'"
        )
        db.execute("UPDATE devices SET effective_profile = wan_profile")

    route_cols = _columns(db, "route_profiles")
    additions = (
        ("health_target", "TEXT NOT NULL DEFAULT '1.1.1.1'"),
        ("health_interval", "INTEGER NOT NULL DEFAULT 10"),
        ("health_timeout", "INTEGER NOT NULL DEFAULT 2"),
        ("fail_threshold", "INTEGER NOT NULL DEFAULT 3"),
        ("recover_threshold", "INTEGER NOT NULL DEFAULT 2"),
        ("health_status", "TEXT NOT NULL DEFAULT 'unknown'"),
        ("health_fail_count", "INTEGER NOT NULL DEFAULT 0"),
        ("health_ok_count", "INTEGER NOT NULL DEFAULT 0"),
        ("health_last_check", "TEXT NOT NULL DEFAULT ''"),
        ("health_last_change", "TEXT NOT NULL DEFAULT ''"),
    )
    for column, declaration in additions:
        if column not in route_cols:
            db.execute(
                f"ALTER TABLE route_profiles ADD COLUMN {column} {declaration}"
            )

    # RouterOS health routing rules require one unique /32
    # destination per WAN profile. Older builds initialized every profile
    # with 1.1.1.1, so assign deterministic unique defaults on collision.
    targets = (
        "1.1.1.1",
        "8.8.8.8",
        "9.9.9.9",
        "208.67.222.222",
        "8.8.4.4",
        "1.0.0.1",
        "149.112.112.112",
        "208.67.220.220",
    )
    rows = db.execute(
        "SELECT profile_id,health_target FROM route_profiles "
        "ORDER BY profile_id"
    ).fetchall()
    seen = set()
    target_index = 0
    for row in rows:
        target = row["health_target"]
        if target and target not in seen:
            seen.add(target)
            continue

        replacement = None
        while target_index < len(targets):
            candidate = targets[target_index]
            target_index += 1
            if candidate not in seen:
                replacement = candidate
                break

        if replacement is not None:
            db.execute(
                """
                UPDATE route_profiles
                SET health_target=?,
                    health_status='unknown',
                    health_fail_count=0,
                    health_ok_count=0,
                    health_last_check='',
                    health_last_change=''
                WHERE profile_id=?
                """,
                (replacement, row["profile_id"]),
            )
            seen.add(replacement)



def _migrate_v020(db):
    cols = _columns(db, "devices")
    additions = (
        ("mac", "TEXT"),
        ("last_seen", "TEXT NOT NULL DEFAULT ''"),
    )
    for column, declaration in additions:
        if column not in cols:
            db.execute(f"ALTER TABLE devices ADD COLUMN {column} {declaration}")

    # SQLite cannot add UNIQUE through ALTER TABLE, so use a partial index.
    db.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_mac_unique
        ON devices(mac)
        WHERE mac IS NOT NULL AND mac <> ''
        """
    )



def _migrate_v030(db):
    cols = _columns(db, "route_profiles")
    if "enabled" not in cols:
        db.execute(
            "ALTER TABLE route_profiles ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1"
        )



def _migrate_v080p6(db):
    """Separate router discovery from WANSINN-managed route profiles."""
    cols = _columns(db, "route_profiles")
    if "managed" not in cols:
        # Existing installations already treated all rows as managed.
        db.execute(
            "ALTER TABLE route_profiles ADD COLUMN managed INTEGER NOT NULL DEFAULT 1"
        )


def _migrate_v0315(db):
    cols = _columns(db, "devices")
    if "router_imported" not in cols:
        db.execute(
            "ALTER TABLE devices ADD COLUMN router_imported INTEGER NOT NULL DEFAULT 0"
        )


def _migrate_v0522(db):
    """Create structured infrastructure records and import the old .env IP list once."""
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS infrastructure_addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # Older installations stored custom infrastructure as a comma-separated .env value.
    # Preserve those addresses once, so updating does not lose the admin's list.
    legacy = str(current_app.config.get("WANSINN_INFRASTRUCTURE_IPS", "")).strip()
    if legacy:
        import re
        from .validation import validate_private_ipv4

        for token in re.split(r"[\\s,;]+", legacy):
            token = token.strip()
            if not token:
                continue
            try:
                ip = validate_private_ipv4(token)
            except ValueError:
                continue
            db.execute(
                """
                INSERT OR IGNORE INTO infrastructure_addresses(ip,name,note)
                VALUES(?,?,?)
                """,
                (ip, "", "Aus älterer Infrastruktur-Liste übernommen"),
            )


def _migrate_v053(db):
    cols = _columns(db, "devices")
    for column, declaration in (
        ("automation_override", "TEXT NOT NULL DEFAULT ''"),
        ("automation_override_at", "TEXT NOT NULL DEFAULT ''"),
    ):
        if column not in cols:
            db.execute(f"ALTER TABLE devices ADD COLUMN {column} {declaration}")
    db.execute("""
        CREATE TABLE IF NOT EXISTS automation_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            action TEXT NOT NULL CHECK (action IN ('offline','online')),
            time_hhmm TEXT NOT NULL,
            weekdays TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6',
            active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
            last_fired_key TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        )
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_automation_rules_due
        ON automation_rules(active,time_hhmm)
    """)


def _migrate_v0534(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS automation_windows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            mode TEXT NOT NULL CHECK (mode IN ('online','offline')),
            start_hhmm TEXT NOT NULL,
            end_hhmm TEXT NOT NULL,
            weekdays TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6',
            active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        )
    """)
    rule_cols = _columns(db, "automation_rules")
    if "window_id" not in rule_cols:
        db.execute("ALTER TABLE automation_rules ADD COLUMN window_id INTEGER")
    if "window_edge" not in rule_cols:
        db.execute("ALTER TABLE automation_rules ADD COLUMN window_edge TEXT")
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_automation_rules_window
        ON automation_rules(window_id)
    """)


def _migrate_v054(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS device_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS device_group_members (
            group_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            PRIMARY KEY(group_id,device_id),
            FOREIGN KEY(group_id) REFERENCES device_groups(id) ON DELETE CASCADE,
            FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_group_members_device ON device_group_members(device_id)")


def _migrate_v055(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            token_hash TEXT NOT NULL,
            token_prefix TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_used_at TEXT NOT NULL DEFAULT ''
        )
    """)



def _ensure_device_type_column(db):
    columns = {
        row["name"]
        for row in db.execute("PRAGMA table_info(devices)").fetchall()
    }
    if "device_type" not in columns:
        db.execute(
            "ALTER TABLE devices ADD COLUMN device_type TEXT NOT NULL DEFAULT 'desktop'"
        )
        db.commit()


def init_db():
    _migrate_legacy_database()
    db = get_db()
    _migrate_devices_table(db)
    db.executescript(SCHEMA)
    _migrate_v1171(db)
    _migrate_v020(db)
    _migrate_v030(db)
    _migrate_v080p6(db)
    _migrate_v0315(db)
    _migrate_v0522(db)
    _migrate_v053(db)
    _migrate_v0534(db)
    _migrate_v054(db)
    _migrate_v055(db)
    db.commit()
    _ensure_device_type_column(db)


def init_app(app):
    app.teardown_appcontext(close_db)
