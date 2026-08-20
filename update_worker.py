#!/usr/bin/env python3
import argparse
import json
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def write_status(path: Path, **data):
    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        **data,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)


def copy_persistent_state(current: Path, target: Path):
    env = current / ".env"
    if env.exists():
        shutil.copy2(env, target / ".env")

    source_instance = current / "instance"
    target_instance = target / "instance"
    if target_instance.exists():
        shutil.rmtree(target_instance)
    if source_instance.exists():
        shutil.copytree(source_instance, target_instance)

    # Keep locally installed/custom addons that are not shipped by the new
    # package. Bundled addons from the update package always win.
    source_addons = current / "addons"
    target_addons = target / "addons"
    if source_addons.exists():
        target_addons.mkdir(parents=True, exist_ok=True)
        for item in source_addons.iterdir():
            destination = target_addons / item.name
            if destination.exists():
                continue
            if item.is_dir():
                shutil.copytree(item, destination)
            elif item.is_file():
                shutil.copy2(item, destination)

    # Reuse the existing virtualenv. Resolve symlink chains so repeated
    # updates do not create .venv -> previous/.venv -> older/.venv chains.
    source_venv = current / ".venv"
    if not source_venv.exists():
        raise RuntimeError("Bestehende .venv fehlt; automatisches Update nicht möglich.")
    real_venv = source_venv.resolve()
    target_venv = target / ".venv"
    if target_venv.exists() or target_venv.is_symlink():
        if target_venv.is_dir() and not target_venv.is_symlink():
            shutil.rmtree(target_venv)
        else:
            target_venv.unlink()
    target_venv.symlink_to(real_venv, target_is_directory=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--current", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--status", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()

    current = Path(args.current).resolve()
    target = Path(args.target).resolve()
    status = Path(args.status).resolve()

    try:
        write_status(
            status,
            state="waiting",
            message="Browser-Antwort abgeschlossen; Update startet.",
            version=args.version,
        )
        time.sleep(2.0)

        write_status(status, state="stopping", message="Stoppe laufendes WANSINN.", version=args.version)
        subprocess.run(
            [str(current / "stop.sh")],
            cwd=current,
            timeout=15,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1.0)

        write_status(status, state="migrating", message="Übernehme lokale Konfiguration und Datenbank.", version=args.version)
        copy_persistent_state(current, target)

        # Mark where rollback can go. The old install is intentionally not
        # modified/deleted; it is the rollback copy.
        rollback = target / "UPDATE_ROLLBACK"
        rollback.write_text(str(current) + "\n", encoding="utf-8")

        write_status(status, state="starting", message="Starte neue WANSINN-Version.", version=args.version)
        log = (target / "update-start.log").open("a", encoding="utf-8")
        subprocess.Popen(
            [str(target / "start.sh")],
            cwd=target,
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )

        write_status(
            status,
            state="started",
            message=f"WANSINN {args.version} wurde gestartet.",
            version=args.version,
            target=str(target),
            rollback=str(current),
        )
    except Exception as exc:
        write_status(
            status,
            state="error",
            message=str(exc),
            version=args.version,
            rollback=str(current),
        )
        # Best effort: if the old service was already stopped, bring it
        # back. The old directory was never modified.
        try:
            log = (current / "update-rollback.log").open("a", encoding="utf-8")
            subprocess.Popen(
                [str(current / "start.sh")],
                cwd=current,
                stdout=log,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        except Exception:
            pass
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
