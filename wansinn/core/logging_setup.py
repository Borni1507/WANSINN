from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logging(app) -> None:
    """Mirror WANSINN logs to a rotating file while keeping terminal output."""
    log_dir = Path(app.instance_path) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "wansinn.log"
    app.config["WANSINN_LOG_FILE"] = str(log_file)

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    # Do not add duplicate handlers on app reload/test creation.
    for handler in root.handlers:
        if getattr(handler, "_wansinn_rotating_file", False):
            return

    # Explicit console handler: do not rely on the WSGI server to provide one.
    # This keeps live diagnostics visible in ./start.sh as well as in wansinn.log.
    if not any(getattr(h, "_wansinn_console", False) for h in root.handlers):
        console = logging.StreamHandler()
        console._wansinn_console = True
        console.setLevel(logging.INFO)
        console.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s:%(name)s:%(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        root.addHandler(console)

    handler = RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    handler._wansinn_rotating_file = True
    handler.setLevel(logging.INFO)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s:%(name)s:%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root.addHandler(handler)

    logging.getLogger(__name__).info(
        "LOG: Web-Log aktiv (%s, 5 MiB × 6 Dateien)",
        log_file,
    )
