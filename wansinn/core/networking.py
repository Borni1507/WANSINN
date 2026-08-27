from __future__ import annotations

import json
import subprocess
from pathlib import Path

NETWORK_HELPER = Path("/usr/local/sbin/wansinn-net-helper")


def provision_testing_ip(management_ip: str, testing_ip: str) -> dict:
    """Ensure WANSINN's local Testing-IP exists on the management interface.

    The privileged helper is intentionally idempotent: if the address already
    exists on the correct interface it returns ``existing=true``; otherwise it
    restores the address after validating the management network and checking
    for a conflicting host.
    """
    management_ip = str(management_ip or "").strip()
    testing_ip = str(testing_ip or "").strip()
    if not management_ip or not testing_ip:
        raise RuntimeError("Management-IP oder Testing-IP ist nicht konfiguriert.")
    if not NETWORK_HELPER.exists():
        raise RuntimeError(
            "WANSINN-Netzwerkhelper fehlt. Bitte ./install.sh erneut ausführen."
        )

    result = subprocess.run(
        ["sudo", "-n", str(NETWORK_HELPER), "add", management_ip, testing_ip],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            (result.stderr or result.stdout).strip()
            or "Testing-IP konnte nicht eingerichtet werden."
        )
    try:
        payload = json.loads(result.stdout)
    except Exception as exc:
        raise RuntimeError(
            "Testing-IP wurde eingerichtet, Antwort war aber ungültig."
        ) from exc
    if not isinstance(payload, dict) or not payload.get("ok"):
        raise RuntimeError("Testing-IP-Helper meldete keinen erfolgreichen Zustand.")
    return payload
