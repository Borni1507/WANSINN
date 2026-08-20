import os
from datetime import timedelta
from pathlib import Path

VERSION_FILE = Path(__file__).resolve().parent.parent / "VERSION"
APP_VERSION = VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "unknown"

from flask import Flask, redirect, render_template, request, url_for
from flask_wtf.csrf import CSRFProtect

from .core.auth import load_logged_in_user
from .core.auth_routes import bp as auth_bp
from .core.db import init_app as init_db_app
from .core.plugins import load_addon
from .core.routes import bp as main_bp
from .core.api import bp as api_bp
from .core.health import start_health_watcher
from .core.discovery import start_discovery_watcher
from .core.logging_setup import configure_logging
from .core.automation import start_automation_watcher
from .core.setup_routes import bp as setup_bp, has_language_choice, is_configured
from .core.i18n import init_app as init_i18n_app, t

csrf = CSRFProtect()


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    project_root = Path(__file__).resolve().parent.parent
    secret_file = project_root / "instance" / "secret.key"
    secret_file.parent.mkdir(parents=True, exist_ok=True)
    if os.environ.get("SECRET_KEY"):
        secret_key = os.environ["SECRET_KEY"]
    elif secret_file.exists():
        secret_key = secret_file.read_text(encoding="utf-8").strip()
    else:
        import secrets
        secret_key = secrets.token_hex(32)
        secret_file.write_text(secret_key, encoding="utf-8")

    app.config.from_mapping(
        SECRET_KEY=secret_key,
        PROJECT_ROOT=str(project_root),
        WANSINN_CONFIGURED=os.environ.get("WANSINN_CONFIGURED", "0") == "1",
        DATABASE=str(Path(app.instance_path) / "wansinn.sqlite"),
        WANSINN_VERSION=APP_VERSION,
        WANSINN_ADDON=os.environ.get("WANSINN_ADDON", ""),
        ADDONS_DIR=str(Path(__file__).resolve().parent.parent / "addons"),
        MIKROTIK_HOST=os.environ.get("MIKROTIK_HOST", ""),
        MIKROTIK_USER=os.environ.get("MIKROTIK_USER", ""),
        MIKROTIK_SSH_KEY=os.environ.get(
            "MIKROTIK_SSH_KEY", str(Path.home() / ".ssh" / "wansinn")
        ),
        MIKROTIK_KNOWN_HOSTS=os.environ.get(
            "MIKROTIK_KNOWN_HOSTS",
            str(Path(app.instance_path) / "ssh" / "known_hosts"),
        ),
        MIKROTIK_PORT=int(os.environ.get("MIKROTIK_PORT", "22")),
        WANSINN_MANAGEMENT_IP=os.environ.get("WANSINN_MANAGEMENT_IP", ""),
        WANSINN_TESTING_IP=os.environ.get("WANSINN_TESTING_IP", ""),
        WANSINN_INFRASTRUCTURE_IPS=os.environ.get("WANSINN_INFRASTRUCTURE_IPS", ""),
        # Proxy headers are ignored unless the administrator explicitly opts in.
        WANSINN_TRUST_PROXY=os.environ.get("WANSINN_TRUST_PROXY", "0") == "1",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("WANSINN_HTTPS", "0") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        WTF_CSRF_TIME_LIMIT=43200,
    )

    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    configure_logging(app)
    app.logger.info("WANSINN: UI gestartet · Version %s", app.config.get("WANSINN_VERSION", "?"))
    init_db_app(app)
    init_i18n_app(app)
    csrf.init_app(app)

    app.extensions["wansinn_addon"] = None
    if app.config["WANSINN_CONFIGURED"] and app.config["WANSINN_ADDON"]:
        app.extensions["wansinn_addon"] = load_addon(
            app.config["WANSINN_ADDON"], Path(app.config["ADDONS_DIR"]), app
        )
        takeover = getattr(app.extensions["wansinn_addon"], "take_control", None)
        if callable(takeover):
            try:
                takeover()
            except Exception:
                app.logger.exception("Router-Exclusive-Control beim Start fehlgeschlagen")

    app.before_request(load_logged_in_user)
    app.register_blueprint(setup_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)
    csrf.exempt(api_bp)

    @app.before_request
    def require_first_run_setup():
        if request.endpoint is None or request.endpoint.startswith("static"):
            return None

        configured = is_configured()

        # A truly fresh installation has no selected UI language yet. Keep the
        # first screen language-neutral and require an explicit choice before
        # the router/admin wizard starts. Upgraded configured installations are
        # intentionally not forced through this gate.
        if not configured and not has_language_choice():
            if request.endpoint == "setup.choose_language":
                return None
            if request.endpoint.startswith("api."):
                return {"ok": False, "error": "WANSINN has not been configured yet."}, 503
            return redirect(url_for("setup.choose_language"))

        if request.endpoint.startswith("setup."):
            return None
        if not configured:
            if request.endpoint.startswith("api."):
                return {"ok": False, "error": t("setup.not_configured")}, 503
            return redirect(url_for("setup.first_run"))
        return None

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("403.html"), 403

    with app.app_context():
        from .core.db import init_db
        init_db()

    start_health_watcher(app)
    start_discovery_watcher(app)
    start_automation_watcher(app)
    return app
