from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

import paramiko
from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import generate_password_hash

from .i18n import SUPPORTED_LANGUAGES, flash_i18n, set_language
from .db import get_db
from .plugins import load_addon
from .validation import validate_private_ipv4

bp = Blueprint("setup", __name__, url_prefix="/setup")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@+-]{1,64}$")


def _provision_testing_ip(management_ip: str, testing_ip: str) -> dict:
    helper = "/usr/local/sbin/wansinn-net-helper"
    if not Path(helper).exists():
        raise RuntimeError("WANSINN-Netzwerkhelper fehlt. Bitte ./install.sh erneut ausführen.")
    result = subprocess.run(
        ["sudo", "-n", helper, "add", management_ip, testing_ip],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip() or "Testing-IP konnte nicht eingerichtet werden.")
    try:
        return __import__("json").loads(result.stdout)
    except Exception as exc:
        raise RuntimeError("Testing-IP wurde eingerichtet, Antwort war aber ungültig.") from exc



def is_configured() -> bool:
    row = get_db().execute(
        "SELECT value FROM settings WHERE key = 'configured'"
    ).fetchone()
    return bool(row and row["value"] == "1")




def has_language_choice() -> bool:
    row = get_db().execute(
        "SELECT value FROM settings WHERE key = 'language'"
    ).fetchone()
    return bool(row and row["value"] in SUPPORTED_LANGUAGES)


@bp.route("/language", methods=("GET", "POST"))
def choose_language():
    # The language gate is only part of first-run setup. Existing configured
    # installations keep their current/default language and can change it in
    # Settings as before.
    if is_configured():
        return redirect(url_for("main.index"))

    if request.method == "POST":
        language = request.form.get("language", "").strip().lower()
        if language in SUPPORTED_LANGUAGES:
            set_language(language)
            return redirect(url_for("setup.first_run"))

    return render_template("select_language.html")


def _write_known_host(path: Path, host: str, port: int, key) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    host_keys = paramiko.HostKeys()
    if path.exists():
        try:
            host_keys.load(str(path))
        except Exception:
            pass
    hostname = host if port == 22 else f"[{host}]:{port}"
    host_keys.add(hostname, key.get_name(), key)
    host_keys.save(str(path))


def _generate_key(key_path: Path) -> None:
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists() and key_path.with_suffix(key_path.suffix + ".pub").exists():
        return
    result = subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t", "ed25519",
            "-N", "",
            "-C", "WANSINN",
            "-f", str(key_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            (result.stderr or result.stdout).strip()
            or "SSH-Key konnte nicht erzeugt werden."
        )
    os.chmod(key_path, 0o600)


def _key_login_works(
    host: str,
    user: str,
    port: int,
    key_path: Path,
    known_hosts: Path,
    test_command: str = ':put "WANSINN_OK"',
) -> bool:
    result = subprocess.run(
        [
            "ssh",
            "-i", str(key_path),
            "-p", str(port),
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
            f"{user}@{host}",
            test_command,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return result.returncode == 0 and "WANSINN_OK" in result.stdout


def _bootstrap_mikrotik(host: str, user: str, password: str, port: int, key_path: Path, known_hosts: Path) -> None:
    _generate_key(key_path)

    # A retry after a partially completed setup may already have a working key.
    if known_hosts.exists() and _key_login_works(host, user, port, key_path, known_hosts):
        return

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=user,
            password=password,
            timeout=7,
            banner_timeout=7,
            auth_timeout=7,
            look_for_keys=False,
            allow_agent=False,
        )
        transport = client.get_transport()
        if transport is None:
            raise RuntimeError("SSH-Transport konnte nicht aufgebaut werden.")

        _write_known_host(
            known_hosts,
            host,
            port,
            transport.get_remote_server_key(),
        )

        public_key = key_path.with_suffix(key_path.suffix + ".pub")
        remote_name = "wansinn-bootstrap.pub"

        sftp = client.open_sftp()
        try:
            sftp.put(str(public_key), remote_name)
        finally:
            sftp.close()

        command = (
            f'/user ssh-keys import public-key-file="{remote_name}" '
            f'user="{user}"'
        )
        _stdin, stdout, stderr = client.exec_command(command, timeout=10)
        status = stdout.channel.recv_exit_status()
        output = (stdout.read() + stderr.read()).decode("utf-8", "replace").strip()

        # RouterOS can report a duplicate on a retry. The real acceptance test
        # is the key-only login below.
        if status != 0 and "already" not in output.lower():
            raise RuntimeError(output or "RouterOS konnte den SSH-Key nicht importieren.")

        try:
            sftp = client.open_sftp()
            try:
                sftp.remove(remote_name)
            finally:
                sftp.close()
        except Exception:
            pass
    finally:
        client.close()

    if not _key_login_works(host, user, port, key_path, known_hosts):
        raise RuntimeError(
            "SSH-Key wurde übertragen, aber der anschließende Key-Login ist fehlgeschlagen."
        )



def _bootstrap_openwrt(
    host: str,
    user: str,
    password: str,
    port: int,
    key_path: Path,
    known_hosts: Path,
) -> None:
    _generate_key(key_path)

    if known_hosts.exists() and _key_login_works(
        host, user, port, key_path, known_hosts, "printf WANSINN_OK"
    ):
        return

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=user,
            password=password,
            timeout=7,
            banner_timeout=7,
            auth_timeout=7,
            look_for_keys=False,
            allow_agent=False,
        )
        transport = client.get_transport()
        if transport is None:
            raise RuntimeError("SSH-Transport konnte nicht aufgebaut werden.")

        _write_known_host(
            known_hosts, host, port, transport.get_remote_server_key()
        )

        public_key = key_path.with_suffix(key_path.suffix + ".pub").read_text(
            encoding="utf-8"
        ).strip()
        quoted = shlex.quote(public_key)
        command = (
            "mkdir -p /etc/dropbear; "
            "touch /etc/dropbear/authorized_keys; "
            f"grep -qxF {quoted} /etc/dropbear/authorized_keys || "
            f"printf '%s\\n' {quoted} >> /etc/dropbear/authorized_keys; "
            "chmod 700 /etc/dropbear; "
            "chmod 600 /etc/dropbear/authorized_keys; "
            "printf WANSINN_OK"
        )
        _stdin, stdout, stderr = client.exec_command(command, timeout=10)
        status = stdout.channel.recv_exit_status()
        output = (stdout.read() + stderr.read()).decode(
            "utf-8", "replace"
        ).strip()
        if status != 0 or "WANSINN_OK" not in output:
            raise RuntimeError(
                output or "SSH-Key konnte auf OpenWrt nicht eingerichtet werden."
            )
    finally:
        client.close()

    if not _key_login_works(
        host, user, port, key_path, known_hosts, "printf WANSINN_OK"
    ):
        raise RuntimeError(
            "SSH-Key wurde übertragen, aber der OpenWrt-Key-Login ist fehlgeschlagen."
        )


def _write_env(
    root: Path,
    addon_id: str,
    host: str,
    user: str,
    port: int,
    key_path: Path,
    known_hosts: Path,
    secret: str,
    management_ip: str,
    testing_ip: str,
) -> None:
    env = "\n".join(
        [
            "WANSINN_CONFIGURED=1",
            f"WANSINN_ADDON={addon_id}",
            f"MIKROTIK_HOST={host}",
            f"MIKROTIK_USER={user}",
            f"MIKROTIK_SSH_KEY={key_path}",
            f"MIKROTIK_KNOWN_HOSTS={known_hosts}",
            f"MIKROTIK_PORT={port}",
            f"SECRET_KEY={secret}",
            f"WANSINN_MANAGEMENT_IP={management_ip}",
            f"WANSINN_TESTING_IP={testing_ip}",
            "WANSINN_HTTPS=0",
            "",
        ]
    )
    (root / ".env").write_text(env, encoding="utf-8")


@bp.route("", methods=("GET", "POST"))
def first_run():
    if is_configured():
        return redirect(url_for("main.index"))

    addons_dir = Path(current_app.config["ADDONS_DIR"])
    addon_choices = []
    for manifest_path in sorted(addons_dir.glob("*/manifest.json")):
        try:
            manifest = __import__("json").loads(manifest_path.read_text(encoding="utf-8"))
            addon_choices.append((manifest["id"], manifest["name"]))
        except Exception:
            continue

    if request.method == "POST":
        addon_id = request.form.get("addon", "").strip()
        host_raw = request.form.get("host", "").strip()
        management_ip_raw = request.form.get("management_ip", "").strip()
        testing_ip_raw = request.form.get("testing_ip", "").strip()
        router_user = request.form.get("router_user", "").strip()
        router_password = request.form.get("router_password", "")
        admin_user = request.form.get("admin_user", "").strip()
        admin_password = request.form.get("admin_password", "")
        admin_password_repeat = request.form.get("admin_password_repeat", "")

        try:
            host = validate_private_ipv4(host_raw)
            management_ip = validate_private_ipv4(management_ip_raw)
            testing_ip = validate_private_ipv4(testing_ip_raw)
            if management_ip == testing_ip:
                raise ValueError("Management-IP und Testing-IP müssen verschieden sein.")
            port = int(request.form.get("port", "22"))
            if not (1 <= port <= 65535):
                raise ValueError("SSH-Port ist ungültig.")
            if not USERNAME_RE.fullmatch(router_user):
                raise ValueError("Router-Benutzername ist ungültig.")
            if addon_id not in {"mikrotik", "glinet"}:
                raise ValueError("Dieses Router-Add-on wird vom Setup noch nicht unterstützt.")
            if addon_id == "glinet" and request.form.get("glinet_takeover_ack") != "1":
                raise ValueError("GL.iNet Exclusive Control muss vor der Einrichtung bestätigt werden.")
            if not router_password:
                raise ValueError("SSH-Passwort fehlt.")
            if len(admin_user) < 3:
                raise ValueError("Admin-Benutzername muss mindestens 3 Zeichen lang sein.")
            if len(admin_password) < 10:
                raise ValueError("Admin-Passwort muss mindestens 10 Zeichen lang sein.")
            if admin_password != admin_password_repeat:
                raise ValueError("Admin-Passwörter stimmen nicht überein.")

            root = Path(current_app.config["PROJECT_ROOT"])
            _provision_testing_ip(management_ip, testing_ip)
            ssh_dir = Path(current_app.instance_path) / "ssh"
            key_path = ssh_dir / "wansinn_ed25519"
            known_hosts = ssh_dir / "known_hosts"

            if addon_id == "mikrotik":
                _bootstrap_mikrotik(
                    host,
                    router_user,
                    router_password,
                    port,
                    key_path,
                    known_hosts,
                )
            elif addon_id == "glinet":
                _bootstrap_openwrt(
                    host,
                    router_user,
                    router_password,
                    port,
                    key_path,
                    known_hosts,
                )

            # Password has served its only purpose. It is never persisted.
            router_password = ""

            db = get_db()
            user_count = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
            if user_count == 0:
                db.execute(
                    "INSERT INTO users(username, password_hash, role) VALUES (?, ?, 'admin')",
                    (admin_user, generate_password_hash(admin_password)),
                )
                admin_id = db.execute(
                    "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
                    (admin_user,),
                ).fetchone()["id"]
            else:
                admin = db.execute(
                    "SELECT id FROM users WHERE role='admin' AND active=1 ORDER BY id LIMIT 1"
                ).fetchone()
                if admin is None:
                    raise RuntimeError("Kein aktiver Administrator vorhanden.")
                admin_id = admin["id"]

            secret = current_app.config["SECRET_KEY"]
            _write_env(
                root, addon_id, host, router_user, port,
                key_path, known_hosts, secret,
                management_ip, testing_ip,
            )

            current_app.config.update(
                WANSINN_CONFIGURED=True,
                WANSINN_ADDON=addon_id,
                MIKROTIK_HOST=host,
                MIKROTIK_USER=router_user,
                MIKROTIK_SSH_KEY=str(key_path),
                MIKROTIK_KNOWN_HOSTS=str(known_hosts),
                MIKROTIK_PORT=port,
                WANSINN_MANAGEMENT_IP=management_ip,
                WANSINN_TESTING_IP=testing_ip,
            )
            current_app.extensions["wansinn_addon"] = load_addon(
                addon_id, addons_dir, current_app
            )

            # One final application-level test through the actual add-on.
            result = current_app.extensions["wansinn_addon"].test_connection()
            if not result.get("ok"):
                raise RuntimeError("Router-Verbindung konnte nicht bestätigt werden.")
            takeover = getattr(current_app.extensions["wansinn_addon"], "take_control", None)
            if callable(takeover):
                takeover(force_snapshot=True)

            db.execute(
                "INSERT OR REPLACE INTO settings(key, value) VALUES ('configured', '1')"
            )
            db.commit()

            session.clear()
            session["user_id"] = admin_id
            session.permanent = True
            flash_i18n(
                "Einrichtung abgeschlossen. SSH-Passwort wurde nicht gespeichert.",
                "success",
            )
            return redirect(url_for("main.index"))
        except Exception as exc:
            current_app.logger.exception("First-Run-Setup fehlgeschlagen")
            flash_i18n(f"Einrichtung fehlgeschlagen: {exc}", "error")

    return render_template("setup.html", addon_choices=addon_choices)
