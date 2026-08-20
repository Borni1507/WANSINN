from __future__ import annotations

import json
import zlib
import shlex
import time
from datetime import datetime, timezone
import ipaddress
import logging
import re
import subprocess
from pathlib import Path
from typing import Any

from wansinn.core.contracts import AddonInfo, HealthCheck, RouterAddon, WanProfile
from wansinn.core.validation import validate_mac, validate_private_ipv4

log = logging.getLogger(__name__)


class GLiNetError(RuntimeError):
    pass


class GLiNetAddon(RouterAddon):
    """GL.iNet/OpenWrt integration with route-scoped health probing."""

    WAN_LABELS = {
        "wan": "WAN 1",
        "secondwan": "WAN 2",
        "wwan": "Wi-Fi WAN",
        "tethering": "Tethering",
    }

    def __init__(self, app, manifest):
        self.app = app
        # Keep the established single-router SSH config storage for
        # compatibility. Router-scoped credentials belong to a later Multi-Router layer.
        self.host = app.config["MIKROTIK_HOST"]
        self.user = app.config["MIKROTIK_USER"]
        self.key = app.config["MIKROTIK_SSH_KEY"]
        self.port = app.config["MIKROTIK_PORT"]
        self.known_hosts = app.config["MIKROTIK_KNOWN_HOSTS"]
        self._takeover_snapshot_path: Path | None = None
        self._takeover_last_check = 0.0
        self._takeover_cached: dict[str, Any] | None = None
        self.info = AddonInfo(
            manifest["id"],
            manifest["name"],
            manifest["vendor"],
            manifest["version"],
            manifest.get("description", ""),
            tuple(manifest.get("capabilities", [])),
        )

    def _ssh(self, command: str, timeout: int = 10) -> str:
        if not Path(self.key).exists():
            raise GLiNetError(f"SSH-Key fehlt: {self.key}")
        try:
            result = subprocess.run(
                [
                    "ssh", "-i", self.key, "-p", str(self.port),
                    "-o", "BatchMode=yes",
                    "-o", "ConnectTimeout=5",
                    "-o", "StrictHostKeyChecking=yes",
                    "-o", f"UserKnownHostsFile={self.known_hosts}",
                    f"{self.user}@{self.host}",
                    command,
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GLiNetError(f"SSH-Verbindung fehlgeschlagen: {exc}") from exc
        if result.returncode:
            raise GLiNetError(
                (result.stderr or result.stdout).strip()
                or "OpenWrt-Befehl fehlgeschlagen"
            )
        return result.stdout.strip()

    def _change_dir(self) -> Path:
        path = Path(self.app.config["PROJECT_ROOT"]) / "instance" / "router-changes"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _kmwan_runtime_state(self) -> dict[str, Any]:
        """Read only the GL.iNet state WANSINN is about to touch."""
        effective = self._ssh("uci -q get kmwan.global.enable 2>/dev/null || echo missing")
        persistent = self._ssh(
            "awk 'BEGIN{s=0} /^config global /{s=1; next} "
            "s && /^[[:space:]]*option enable /{gsub(/\\047/,\"\",$3); print $3; exit} "
            "s && /^config /{exit}' /etc/config/kmwan 2>/dev/null || true"
        ).strip() or "missing"
        autostart = self._ssh(
            "if /etc/init.d/kmwan enabled >/dev/null 2>&1; then echo 1; else echo 0; fi"
        ).strip()
        proc_state = self._ssh("cat /proc/gl-kmwan/config 2>/dev/null || true").strip()
        board = self._board()
        release = board.get("release", {}) if isinstance(board.get("release", {}), dict) else {}
        return {
            "effective_enable": effective.strip(),
            "persistent_enable": persistent,
            "autostart_enabled": autostart == "1",
            "proc_config": proc_state,
            "model": str(board.get("model") or ""),
            "board_name": str(board.get("board_name") or ""),
            "kernel": str(board.get("kernel") or ""),
            "openwrt_version": str(release.get("version") or ""),
            "openwrt_revision": str(release.get("revision") or ""),
            "glinet_version": self._ssh("cat /etc/glversion 2>/dev/null || true").strip(),
        }

    def _write_takeover_snapshot(self, state: dict[str, Any]) -> Path:
        """Persist rollback facts before the first exclusive takeover."""
        if self._takeover_snapshot_path and self._takeover_snapshot_path.exists():
            return self._takeover_snapshot_path

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stem = f"glinet-takeover-{stamp}"
        directory = self._change_dir()
        json_path = directory / f"{stem}.json"
        sh_path = directory / f"{stem}-revert.sh"
        payload = {
            "format": 1,
            "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "router": {
                "host": self.host,
                "port": self.port,
                "user": self.user,
                "addon": self.info.id,
                "addon_version": self.info.version,
            },
            "original": state,
            "changes": [
                {
                    "target": "kmwan.global.enable",
                    "original_effective": state.get("effective_enable"),
                    "original_persistent": state.get("persistent_enable"),
                    "session_value": "0",
                    "persistent_write": False,
                },
                {
                    "target": "/etc/init.d/kmwan",
                    "action": "stop",
                    "original_autostart_enabled": bool(state.get("autostart_enabled")),
                },
            ],
            "recovery_note": "WANSINN verändert kmwan nur zur Laufzeit. Das Recovery-Script stellt den vorgefundenen Runtime-Zustand wieder her.",
        }
        json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        original_effective = str(state.get("effective_enable", "1"))
        if original_effective not in {"0", "1"}:
            original_effective = str(state.get("persistent_enable", "1"))
        if original_effective not in {"0", "1"}:
            original_effective = "1"
        restore_service = "/etc/init.d/kmwan start" if original_effective == "1" else "/etc/init.d/kmwan stop"
        script_lines = [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "# WANSINN GL.iNet recovery script",
            f"# Router: {state.get('model', 'unknown')}",
            f"# GL.iNet firmware: {state.get('glinet_version', 'unknown')}",
            f"# OpenWrt: {state.get('openwrt_version', 'unknown')} {state.get('openwrt_revision', '')}",
            "# Generated before Exclusive Control takeover.",
            "",
            f"SSH_KEY=${{WANSINN_SSH_KEY:-{shlex.quote(str(self.key))}}}",
            f"ROUTER=${{WANSINN_ROUTER:-{shlex.quote(f'{self.user}@{self.host}')}}}",
            f"PORT=${{WANSINN_SSH_PORT:-{self.port}}}",
            f"KNOWN_HOSTS=${{WANSINN_KNOWN_HOSTS:-{shlex.quote(str(self.known_hosts))}}}",
            "",
            "ssh -i \"$SSH_KEY\" -p \"$PORT\" \\",
            "  -o StrictHostKeyChecking=yes \\",
            "  -o UserKnownHostsFile=\"$KNOWN_HOSTS\" \\",
            "  \"$ROUTER\" <<'WANSINN_RECOVERY'",
            f"uci set kmwan.global.enable='{original_effective}'",
            restore_service,
            "WANSINN_RECOVERY",
            "",
            "echo \"WANSINN: GL.iNet kmwan runtime state restored.\"",
            "",
        ]
        sh_path.write_text("\n".join(script_lines), encoding="utf-8")
        sh_path.chmod(0o700)
        self._takeover_snapshot_path = json_path
        log.warning("GL.iNet Exclusive: Änderungsdatei geschrieben: %s", json_path)
        log.warning("GL.iNet Exclusive: Recovery-Script geschrieben: %s", sh_path)
        return json_path

    def _kmwan_control_probe(self) -> dict[str, Any]:
        raw = self._ssh(
            "printf 'ENABLE='; uci -q get kmwan.global.enable 2>/dev/null || echo missing; "
            "printf 'PROC='; cat /proc/gl-kmwan/config 2>/dev/null | tr '\\n' ';' || true",
            timeout=8,
        )
        values = {}
        for line in raw.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().rstrip(";")
        effective = values.get("ENABLE", "missing")
        proc_state = values.get("PROC", "")
        return {
            "effective_enable": effective,
            "proc_config": proc_state,
            "exclusive": effective == "0" and not proc_state,
        }

    def takeover_status(self) -> dict[str, Any]:
        state = self._kmwan_runtime_state()
        proc_empty = not bool(str(state.get("proc_config") or "").strip())
        effective_off = str(state.get("effective_enable")) == "0"
        return {**state, "exclusive": effective_off and proc_empty, "snapshot": str(self._takeover_snapshot_path or "")}

    def take_control(self, *, force_snapshot: bool = False) -> dict[str, Any]:
        """Temporarily silence GL.iNet kmwan and verify exclusive control."""
        before = self._kmwan_runtime_state()
        if force_snapshot or self._takeover_snapshot_path is None:
            self._write_takeover_snapshot(before)
        self._ssh("uci set kmwan.global.enable='0'", timeout=8)
        self._ssh("/etc/init.d/kmwan stop", timeout=12)
        after = self.takeover_status()
        if not after["exclusive"]:
            raise GLiNetError(
                "GL.iNet Exclusive Control konnte kmwan nicht vollständig stoppen "
                f"(enable={after.get('effective_enable')}, proc={after.get('proc_config')!r})."
            )
        self._takeover_cached = after
        self._takeover_last_check = time.monotonic()
        log.warning("GL.iNet Exclusive: kmwan temporär gestoppt; WANSINN besitzt das Routing")
        return after

    def ensure_control(self) -> dict[str, Any]:
        """Re-take control after a router reboot without replacing the snapshot."""
        now = time.monotonic()
        if self._takeover_cached and now - self._takeover_last_check < 5.0:
            return self._takeover_cached
        status = self._kmwan_control_probe()
        self._takeover_last_check = now
        self._takeover_cached = status
        if status["exclusive"]:
            return status
        log.warning("GL.iNet Exclusive: kmwan wieder aktiv erkannt; Übernahme wird erneuert")
        status = self.take_control(force_snapshot=False)
        self._takeover_last_check = time.monotonic()
        self._takeover_cached = status
        return status

    def _ubus(self, object_name: str) -> dict[str, Any]:
        raw = self._ssh(f"ubus call {object_name} status", timeout=8)
        try:
            value = json.loads(raw or "{}")
        except json.JSONDecodeError as exc:
            raise GLiNetError(f"Ungültige ubus-Antwort für {object_name}") from exc
        if not isinstance(value, dict):
            raise GLiNetError(f"Unerwartete ubus-Antwort für {object_name}")
        return value

    def _board(self) -> dict[str, Any]:
        raw = self._ssh("ubus call system board", timeout=8)
        try:
            value = json.loads(raw or "{}")
        except json.JSONDecodeError as exc:
            raise GLiNetError("Systeminformationen konnten nicht gelesen werden") from exc
        return value if isinstance(value, dict) else {}

    def _uci_interfaces(self) -> dict[str, dict[str, str]]:
        raw = self._ssh("uci -q show network")
        result: dict[str, dict[str, str]] = {}
        for line in raw.splitlines():
            line = line.strip()
            section = re.fullmatch(r"network\.([A-Za-z0-9_]+)=interface", line)
            if section:
                result.setdefault(section.group(1), {})
                continue
            option = re.fullmatch(
                r"network\.([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)='?(.*?)'?", line
            )
            if option and option.group(1) in result:
                result[option.group(1)][option.group(2)] = option.group(3).strip("'")
        return result

    @staticmethod
    def _gateway(status: dict[str, Any]) -> str:
        for route in status.get("route", []) or []:
            if not isinstance(route, dict):
                continue
            if route.get("target") == "0.0.0.0" and int(route.get("mask", 0)) == 0:
                return str(route.get("nexthop") or route.get("gateway") or "")
        return ""

    @staticmethod
    def _address(status: dict[str, Any]) -> str:
        values = status.get("ipv4-address", []) or []
        if values and isinstance(values[0], dict):
            return str(values[0].get("address") or "")
        return ""

    def _wan_sections(self) -> list[str]:
        interfaces = self._uci_interfaces()
        result = []
        for name in ("wan", "secondwan", "wwan", "tethering"):
            if name not in interfaces:
                continue
            if name not in {"wan", "secondwan"} and interfaces[name].get("disabled") == "1":
                continue
            result.append(name)
        return result

    def _wan_state(self, name: str) -> dict[str, Any]:
        cfg = self._uci_interfaces().get(name, {})
        try:
            status = self._ubus(f"network.interface.{name}")
        except GLiNetError:
            status = {}

        device = str(
            status.get("l3_device")
            or status.get("device")
            or cfg.get("device")
            or cfg.get("ifname")
            or ""
        )
        return {
            "id": name,
            "label": self.WAN_LABELS.get(name, name),
            "device": device,
            "up": bool(status.get("up")),
            "pending": bool(status.get("pending")),
            "gateway": self._gateway(status),
            "address": self._address(status),
            "proto": str(cfg.get("proto") or status.get("proto") or ""),
            "metric": str(cfg.get("metric") or ""),
            "disabled": cfg.get("disabled") == "1",
        }

    def managed_profiles(self) -> list[dict[str, str]]:
        profiles = []
        for name in self._wan_sections():
            state = self._wan_state(name)
            profiles.append({
                "id": name,
                "label": state["label"],
                "gateway": state["gateway"],
            })
        return profiles

    def create_route_profile(self, name: str, gateway: str) -> dict[str, str]:
        """Adopt one existing OpenWrt WAN into WANSINN management.

        GL.iNet/OpenWrt already owns the physical interface configuration.
        WANSINN therefore does not create VLANs, DHCP clients or interfaces
        here.  The administrator explicitly adds a WAN by its gateway and we
        bind that WANSINN profile to the matching router interface.
        """
        label = str(name or "").strip()
        if not label:
            raise GLiNetError("Profilname darf nicht leer sein.")
        if len(label) > 64:
            raise GLiNetError("Profilname darf maximal 64 Zeichen lang sein.")

        try:
            gateway = str(ipaddress.IPv4Address(str(gateway or "").strip()))
        except ipaddress.AddressValueError as exc:
            raise GLiNetError("Gateway ist keine gültige IPv4-Adresse.") from exc

        matches = []
        for profile_id in self._wan_sections():
            state = self._wan_state(profile_id)
            if state.get("gateway") == gateway:
                matches.append((profile_id, state))

        if not matches:
            raise GLiNetError(
                f"Kein vorhandenes GL.iNet-WAN mit Gateway {gateway} gefunden."
            )
        if len(matches) > 1:
            ids = ", ".join(item[0] for item in matches)
            raise GLiNetError(
                f"Gateway {gateway} ist nicht eindeutig ({ids})."
            )

        profile_id, state = matches[0]
        return {
            "id": profile_id,
            "label": label,
            "gateway": gateway,
        }

    def profiles(self) -> list[WanProfile]:
        profiles = [WanProfile("auto", "AUTO")]
        profiles.extend(
            WanProfile(item["id"], item["label"])
            for item in self.managed_profiles()
        )
        profiles.append(WanProfile("offline", "OFFLINE"))
        return profiles

    def profile_availability(self) -> dict[str, bool]:
        return {
            name: bool(self._wan_state(name)["up"])
            for name in self._wan_sections()
        }

    def probe_profile(self, profile_id: str, target: str, timeout: int = 2) -> bool:
        """Probe a target through one explicitly selected OpenWrt interface.

        The router gets one temporary /32 route for the probe target. This does
        not change the default route and is removed in a shell trap even when
        ping fails.
        """
        if profile_id not in self._wan_sections():
            raise GLiNetError(f"Unbekanntes OpenWrt-Profil: {profile_id}")

        state = self._wan_state(profile_id)
        if state["disabled"]:
            return False
        device = state["device"]
        if not device:
            return False

        # health_target is already IPv4-oriented in WANSINN. Keep the remote
        # shell input deliberately strict because this command runs as root.
        try:
            import ipaddress
            target_ip = str(ipaddress.IPv4Address(target))
        except Exception as exc:
            raise GLiNetError("Healthcheck-Ziel muss eine IPv4-Adresse sein.") from exc

        timeout = max(1, min(int(timeout), 10))
        gateway = state["gateway"]

        # Quote only values that passed strict validation / kernel discovery.
        safe_device = re.fullmatch(r"[A-Za-z0-9_.:@+-]+", device)
        if not safe_device:
            raise GLiNetError("Unsicherer Interface-Name vom Router erhalten.")

        route = f"{target_ip}/32"
        if gateway:
            try:
                gateway = str(ipaddress.IPv4Address(gateway))
            except Exception as exc:
                raise GLiNetError("Ungültiges Gateway vom Router erhalten.") from exc
            add_cmd = f"ip -4 route replace {route} via {gateway} dev {device}"
        else:
            add_cmd = f"ip -4 route replace {route} dev {device}"

        command = (
            "set -e; "
            f"{add_cmd}; "
            f"trap 'ip -4 route del {route} >/dev/null 2>&1 || true' EXIT; "
            f"ping -4 -I {device} -c 1 -W {timeout} {target_ip} >/dev/null 2>&1"
        )
        try:
            self._ssh(command, timeout=timeout + 6)
            return True
        except GLiNetError:
            # A failed ping is a health result, not an add-on crash. Verify
            # cleanup once more because Dropbear/BusyBox shells vary slightly.
            try:
                self._ssh(f"ip -4 route del {route} >/dev/null 2>&1 || true", timeout=4)
            except Exception:
                log.exception("Temporäre OpenWrt-Probe-Route konnte nicht bereinigt werden")
            return False

    def test_connection(self) -> dict[str, Any]:
        ok = self._ssh("printf WANSINN_OK") == "WANSINN_OK"
        board = self._board() if ok else {}
        return {
            "ok": ok,
            "host": self.host,
            "user": self.user,
            "model": board.get("model", ""),
            "hostname": board.get("hostname", ""),
        }

    @staticmethod
    def _pbr_table_id(profile: str) -> int:
        """Stable WANSINN-owned numeric table in a private runtime range."""
        return 18000 + (zlib.crc32(profile.encode("utf-8")) % 700)

    @staticmethod
    def _pbr_rule_priority(ip: str) -> int:
        """Stable per-client rule priority in a WANSINN-owned range."""
        addr = ipaddress.IPv4Address(ip)
        return 19000 + (int(addr) % 700)

    def _validate_client_ip(self, ip: str) -> str:
        raw = "" if ip is None else str(ip).strip()
        try:
            # Be liberal at the add-on boundary. Normal WANSINN device records
            # contain a plain address, but imported/test records may carry a
            # harmless CIDR suffix.
            if "/" in raw:
                value = ipaddress.IPv4Interface(raw).ip
            else:
                value = ipaddress.IPv4Address(raw)
        except Exception as exc:
            raise GLiNetError(
                f"Geräte-IP ist keine gültige IPv4-Adresse: {raw!r}"
            ) from exc
        if not value.is_private:
            raise GLiNetError(
                f"Geräte-IP muss eine private IPv4-Adresse sein: {value}"
            )
        return str(value)

    def _remove_wansinn_rules(self, ip: str) -> None:
        """Remove only WANSINN-owned rules for one source IP."""
        ip = self._validate_client_ip(ip)
        # Delete matching source rules in our priority range. Re-read after
        # every deletion because `ip rule del` removes one matching rule.
        command = (
            "while ip -4 rule show | "
            f"grep -E '^[0-9]+:[[:space:]]+from {ip}([[:space:]]|$)' | "
            "awk -F: '$1 >= 19000 && $1 < 19700 {print $1}' | "
            "head -n1 | grep -q .; do "
            "pref=$(ip -4 rule show | "
            f"grep -E '^[0-9]+:[[:space:]]+from {ip}([[:space:]]|$)' | "
            "awk -F: '$1 >= 19000 && $1 < 19700 {print $1}' | head -n1); "
            "ip -4 rule del pref \"$pref\"; "
            "done"
        )
        self._ssh(command, timeout=8)

    def _flush_client_connections(self, ip: str) -> None:
        """Best-effort conntrack flush so a route change applies immediately."""
        ip = self._validate_client_ip(ip)
        command = (
            "if command -v conntrack >/dev/null 2>&1; then "
            f"conntrack -D -s {ip} >/dev/null 2>&1 || true; "
            f"conntrack -D -d {ip} >/dev/null 2>&1 || true; "
            "fi"
        )
        try:
            self._ssh(command, timeout=8)
        except Exception:
            log.exception("Conntrack für %s konnte nicht geleert werden", ip)

    def _wan_devices(self) -> list[str]:
        devices: list[str] = []
        for name in self._wan_sections():
            state = self._wan_state(name)
            device = str(state.get("device") or "").strip()
            if not device:
                continue
            if not re.fullmatch(r"[A-Za-z0-9_.:@+-]+", device):
                continue
            if device not in devices:
                devices.append(device)
        return devices

    def _ensure_offline_firewall(self) -> None:
        """Create WANSINN's isolated nftables objects if needed.

        The forward hook only drops packets from OFFLINE clients when they
        leave through one of the currently discovered WAN devices. LAN-to-LAN
        traffic therefore remains available.
        """
        devices = self._wan_devices()
        if not devices:
            raise GLiNetError("Keine WAN-Interfaces für OFFLINE erkannt.")

        # OpenWrt/GL.iNet already provides nft. Keep WANSINN in its own table so
        # we never edit fw4/GL.iNet-owned chains.
        self._ssh(
            "nft list table inet wansinn >/dev/null 2>&1 || "
            "nft add table inet wansinn",
            timeout=8,
        )
        self._ssh(
            "nft list set inet wansinn offline4 >/dev/null 2>&1 || "
            "nft 'add set inet wansinn offline4 { type ipv4_addr; }'",
            timeout=8,
        )
        self._ssh(
            "nft list chain inet wansinn forward >/dev/null 2>&1 || "
            "nft 'add chain inet wansinn forward "
            "{ type filter hook forward priority -5; policy accept; }'",
            timeout=8,
        )

        # Rebuild only WANSINN's chain so WAN device changes are reflected.
        self._ssh("nft flush chain inet wansinn forward", timeout=8)
        quoted_devices = ", ".join(f'"{device}"' for device in devices)
        self._ssh(
            "nft 'add rule inet wansinn forward "
            f'ip saddr @offline4 oifname {{ {quoted_devices} }} drop'
            "'",
            timeout=8,
        )

    def _set_offline_state(self, ip: str, offline: bool) -> None:
        ip = self._validate_client_ip(ip)
        self._ensure_offline_firewall()

        if offline:
            self._ssh(
                "nft 'add element inet wansinn offline4 "
                f"{{ {ip} }}' 2>/dev/null || true",
                timeout=8,
            )
        else:
            self._ssh(
                "nft 'delete element inet wansinn offline4 "
                f"{{ {ip} }}' 2>/dev/null || true",
                timeout=8,
            )

    def _is_offline(self, ip: str) -> bool:
        ip = self._validate_client_ip(ip)
        try:
            output = self._ssh(
                "nft list set inet wansinn offline4 2>/dev/null || true",
                timeout=8,
            )
        except Exception:
            return False
        # nft renders set members as plain IPv4 addresses.
        return bool(re.search(rf"(?<![0-9.]){re.escape(ip)}(?![0-9.])", output))

    def set_device_profile(self, ip: str, profile: str) -> None:
        """Route one client through a selected OpenWrt uplink.

        Keep all routing changes inside WANSINN-owned runtime
        policy tables. Every selected WAN table gets a terminal unreachable
        default route with a deliberately worse metric. While the selected
        WAN route exists it wins; if OpenWrt/netifd removes that route, the
        unreachable route terminates policy lookup instead of falling through
        to the router's main table / native Multi-WAN logic.
        """
        ip = self._validate_client_ip(ip)
        profile = str(profile).strip()

        if profile == "auto":
            # Release-to-native is intentionally retained for unmanaged/testing
            # callers. Managed WANSINN AUTO devices never call this branch: the
            # core resolves AUTO to a concrete effective profile first.
            self._remove_wansinn_rules(ip)
            self._set_offline_state(ip, False)
            self._flush_client_connections(ip)
            return

        if profile == "offline":
            self._remove_wansinn_rules(ip)
            self._set_offline_state(ip, True)
            self._flush_client_connections(ip)
            return

        if profile not in self._wan_sections():
            raise GLiNetError(f"Unbekanntes OpenWrt-Profil: {profile}")

        state = self._wan_state(profile)
        if state["disabled"]:
            raise GLiNetError(f"{profile} ist auf OpenWrt deaktiviert.")
        device = state["device"]
        if not device:
            raise GLiNetError(f"{profile} hat kein aktives Interface.")

        if not re.fullmatch(r"[A-Za-z0-9_.:@+-]+", device):
            raise GLiNetError("Unsicherer Interface-Name vom Router erhalten.")

        gateway = state["gateway"]
        if gateway:
            try:
                gateway = str(ipaddress.IPv4Address(gateway))
            except Exception as exc:
                raise GLiNetError("Ungültiges Gateway vom Router erhalten.") from exc

        table = self._pbr_table_id(profile)
        pref = self._pbr_rule_priority(ip)

        # A real WAN profile releases a previous OFFLINE state first.
        self._set_offline_state(ip, False)

        # Build the WANSINN table from the selected uplink only.
        if gateway:
            route_cmd = f"ip -4 route replace table {table} default via {gateway} dev {device}"
        else:
            route_cmd = f"ip -4 route replace table {table} default dev {device}"

        # Build fail-closed semantics before attaching the client rule. The
        # selected WAN route has the normal metric (0). The unreachable route
        # is only used if that WAN route disappears or cannot be installed.
        # This prevents Linux RPDB from continuing to `lookup main`, where
        # GL.iNet/OpenWrt may legitimately choose another WAN.
        fail_closed_cmd = (
            f"ip -4 route replace unreachable default metric 32760 table {table}"
        )

        self._remove_wansinn_rules(ip)
        self._ssh(fail_closed_cmd, timeout=8)
        self._ssh(route_cmd, timeout=8)
        self._ssh(
            f"ip -4 rule add pref {pref} from {ip}/32 lookup {table}",
            timeout=8,
        )
        self._ssh("ip -4 route flush cache >/dev/null 2>&1 || true", timeout=5)
        self._flush_client_connections(ip)

    def apply_effective_profile(self, ip: str, profile: str) -> None:
        # AUTO is resolved by the WANSINN core.  The add-on receives only the
        # effective WAN/OFFLINE target and applies the same fail-closed policy
        # used by manual routing.
        if profile == "auto":
            raise GLiNetError("AUTO muss vor dem Router-Aufruf zu einem effektiven Profil aufgelöst werden.")
        self.set_device_profile(ip, profile)

    def get_device_profile(self, ip: str) -> str:
        ip = self._validate_client_ip(ip)

        if self._is_offline(ip):
            return "offline"

        rules = self._ssh("ip -4 rule show", timeout=8)

        table_to_profile = {
            self._pbr_table_id(profile): profile
            for profile in self._wan_sections()
        }
        for line in rules.splitlines():
            if f"from {ip}" not in line:
                continue
            m_pref = re.match(r"\s*(\d+):", line)
            m_lookup = re.search(r"\blookup\s+(\d+)\b", line)
            if not m_pref or not m_lookup:
                continue
            pref = int(m_pref.group(1))
            table = int(m_lookup.group(1))
            if 19000 <= pref < 19700 and table in table_to_profile:
                return table_to_profile[table]

        return "auto"

    def discovery_infrastructure_ips(self) -> set[str]:
        result = {self.host}
        for name in self._wan_sections():
            gateway = self._wan_state(name)["gateway"]
            if gateway:
                result.add(gateway)
        return result

    def _discovery_client_networks(self) -> tuple[list[ipaddress.IPv4Network], set[str]]:
        """Return router-side client networks and their L3 devices.

        Discovery runs on the router so it can see clients behind routed VLANs.
        We derive the observation boundary from active OpenWrt interfaces and
        deliberately exclude WANSINN WAN profiles, loopback and point-to-point
        interfaces. This keeps provider gateways out without hard-coding br-lan.
        """
        wan_sections = set(self._wan_sections())
        try:
            raw = self._ssh("ubus call network.interface dump", timeout=8)
            dump = json.loads(raw or "{}")
        except (GLiNetError, json.JSONDecodeError):
            dump = {}

        networks: list[ipaddress.IPv4Network] = []
        devices: set[str] = set()
        for item in dump.get("interface", []) if isinstance(dump, dict) else []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("interface") or "").strip()
            if not name or name in wan_sections or name == "loopback":
                continue
            if not bool(item.get("up")):
                continue

            device = str(item.get("l3_device") or item.get("device") or "").strip()
            if not device or device == "lo":
                continue

            item_networks: list[ipaddress.IPv4Network] = []
            for addr in item.get("ipv4-address", []) or []:
                if not isinstance(addr, dict):
                    continue
                address = str(addr.get("address") or "").strip()
                try:
                    mask = int(addr.get("mask", 32))
                    interface = ipaddress.IPv4Interface(f"{address}/{mask}")
                except (ValueError, TypeError):
                    continue
                if not interface.ip.is_private or interface.ip.is_loopback:
                    continue
                item_networks.append(interface.network)

            # Interfaces without an IPv4 subnet are not useful for ARP/neighbor
            # based client discovery. WireGuard/VPS links therefore stay out.
            if not item_networks:
                continue
            networks.extend(item_networks)
            devices.add(device)

        # De-duplicate while preserving deterministic ordering for logs/tests.
        unique_networks = sorted(set(networks), key=lambda n: (int(n.network_address), n.prefixlen))
        return unique_networks, devices

    @staticmethod
    def _ip_in_networks(ip: str, networks: list[ipaddress.IPv4Network]) -> bool:
        try:
            value = ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            return False
        return any(value in network for network in networks)

    def discover_devices(self) -> list[dict[str, str]]:
        """Observe LAN/VLAN clients for the shared WANSINN discovery core.

        GL.iNet does not expose the RouterOS-style discovery API we use on
        MikroTik. OpenWrt already has two excellent local sensors though:
        dnsmasq DHCP leases provide names and stable primary addresses, while
        the kernel neighbor table also sees static/non-DHCP clients.

        The add-on only observes and normalizes router-local facts. Device
        identity, adoption, MAC/IP moves and de-duplication remain in
        ``wansinn.core.discovery`` for every router backend.
        """
        networks, client_devices = self._discovery_client_networks()
        if not networks:
            log.warning("DISCOVERY/GLINET: keine aktiven LAN/VLAN-Netze gefunden")
            return []

        by_mac: dict[str, dict[str, str]] = {}

        # dnsmasq lease format:
        # <expiry> <mac> <ip> <hostname> <client-id>
        try:
            leases = self._ssh("cat /tmp/dhcp.leases 2>/dev/null || true", timeout=8)
        except Exception:
            leases = ""
        for line in leases.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            mac_raw, ip_raw, hostname = parts[1], parts[2], parts[3]
            try:
                mac = validate_mac(mac_raw)
                ip = validate_private_ipv4(ip_raw)
            except ValueError:
                continue
            if not self._ip_in_networks(ip, networks):
                continue
            if hostname in {"*", "-"}:
                hostname = ""
            by_mac[mac] = {
                "mac": mac,
                "ip": ip,
                "name": hostname[:80],
                "source": "dhcp",
                "interface": "",
                "status": "",
            }

        try:
            neighbors = self._ssh("ip -4 neigh show 2>/dev/null || ip neigh show", timeout=8)
        except Exception:
            neighbors = ""

        state_rank = {
            "PERMANENT": 6,
            "REACHABLE": 5,
            "DELAY": 4,
            "PROBE": 3,
            "STALE": 2,
            "NOARP": 1,
        }
        neighbor_choice: dict[str, tuple[int, str, str, str]] = {}
        for line in neighbors.splitlines():
            parts = line.split()
            if len(parts) < 4 or "dev" not in parts or "lladdr" not in parts:
                continue
            try:
                dev_index = parts.index("dev")
                mac_index = parts.index("lladdr")
                ip_raw = parts[0]
                device = parts[dev_index + 1]
                mac_raw = parts[mac_index + 1]
            except (ValueError, IndexError):
                continue
            state = parts[-1].upper()
            if state in {"FAILED", "INCOMPLETE"}:
                continue
            if client_devices and device not in client_devices:
                continue
            try:
                mac = validate_mac(mac_raw)
                ip = validate_private_ipv4(ip_raw)
            except ValueError:
                continue
            if not self._ip_in_networks(ip, networks):
                continue

            rank = state_rank.get(state, 0)
            previous = neighbor_choice.get(mac)
            candidate = (rank, ip, device, state)
            if previous is None or candidate[0] > previous[0] or (candidate[0] == previous[0] and candidate[1] < previous[1]):
                neighbor_choice[mac] = candidate

        for mac, (_rank, ip, device, state) in neighbor_choice.items():
            current = by_mac.get(mac)
            if current is None:
                by_mac[mac] = {
                    "mac": mac,
                    "ip": ip,
                    "name": "",
                    "source": "neigh",
                    "interface": device[:80],
                    "status": state,
                }
            else:
                # Keep DHCP as the primary address/name when present. This
                # avoids turning one multi-address host into alternating device
                # identities (e.g. one client with multiple IPs on the same MAC).
                current["interface"] = device[:80]
                current["source"] = "dhcp+neigh"
                current["status"] = state

        result = sorted(
            by_mac.values(),
            key=lambda item: (
                item.get("name", "").lower(),
                item.get("ip", ""),
                item.get("mac", ""),
            ),
        )
        log.info(
            "DISCOVERY/GLINET: %s Gerät(e) aus %s Netz(en) auf %s",
            len(result), len(networks), ",".join(sorted(client_devices)) or "unbekannt",
        )
        return result

    def health_check(self) -> list[HealthCheck]:
        """Validate the OpenWrt building blocks WANSINN depends on.

        WAN presence is intentionally NOT a Medic concern. WANs become relevant
        only when the user creates WANSINN route profiles for them.
        """
        checks: list[HealthCheck] = []

        try:
            connection = self.test_connection()
            checks.append(
                HealthCheck(
                    "ssh",
                    "SSH-Verbindung",
                    "ok" if connection["ok"] else "error",
                    "per SSH erreichbar" if connection["ok"] else "SSH nicht erreichbar",
                    (f"Benutzer: {self.user}",),
                )
            )
        except Exception as exc:
            return [
                HealthCheck(
                    "ssh",
                    "SSH-Verbindung",
                    "error",
                    "SSH-Prüfung fehlgeschlagen",
                    (str(exc),),
                )
            ]

        # OpenWrt / GL.iNet platform identity
        try:
            board = self._board()
            release = board.get("release", {})
            if not isinstance(release, dict):
                release = {}
            glversion = self._ssh("cat /etc/glversion 2>/dev/null || true")

            checks.append(
                HealthCheck(
                    "openwrt",
                    "OpenWrt / GL.iNet",
                    "ok",
                    "Router erkannt",
                    (
                        f"Modell: {board.get('model', 'unbekannt')}",
                        f"Hostname: {board.get('hostname', 'unbekannt')}",
                        f"OpenWrt: {release.get('version', 'unbekannt')}",
                        f"GL.iNet: {glversion or 'unbekannt'}",
                        f"Kernel: {board.get('kernel', 'unbekannt')}",
                    ),
                )
            )
        except Exception as exc:
            checks.append(
                HealthCheck(
                    "openwrt",
                    "OpenWrt / GL.iNet",
                    "warning",
                    "Systeminformationen unvollständig",
                    (str(exc),),
                )
            )

        # UCI must be readable, because future route/profile writes rely on it.
        try:
            interfaces = self._uci_interfaces()
            checks.append(
                HealthCheck(
                    "uci-network",
                    "OpenWrt-Netzwerkkonfiguration",
                    "ok",
                    "UCI-Netzwerkkonfiguration lesbar",
                    (f"{len(interfaces)} Interface-Sektion(en) erkannt",),
                )
            )
        except Exception as exc:
            checks.append(
                HealthCheck(
                    "uci-network",
                    "OpenWrt-Netzwerkkonfiguration",
                    "error",
                    "UCI-Netzwerkkonfiguration nicht lesbar",
                    (str(exc),),
                )
            )

        # ubus is the runtime source of truth for interface status.
        try:
            raw = self._ssh("ubus list 'network.interface.*'")
            interface_objects = [line.strip() for line in raw.splitlines() if line.strip()]
            status = "ok" if interface_objects else "warning"
            message = (
                "ubus Netzwerkstatus verfügbar"
                if interface_objects
                else "Keine ubus Netzwerk-Interfaces gefunden"
            )
            checks.append(
                HealthCheck(
                    "ubus-network",
                    "OpenWrt Runtime-Netzwerk",
                    status,
                    message,
                    (f"{len(interface_objects)} Interface-Objekt(e)",),
                )
            )
        except Exception as exc:
            checks.append(
                HealthCheck(
                    "ubus-network",
                    "OpenWrt Runtime-Netzwerk",
                    "error",
                    "ubus Netzwerkstatus nicht verfügbar",
                    (str(exc),),
                )
            )

        # iproute2 is required for route/rule discovery and future policy work.
        try:
            route_output = self._ssh("ip -4 route show")
            rule_output = self._ssh("ip -4 rule show")
            checks.append(
                HealthCheck(
                    "iproute2",
                    "Routing-Werkzeuge",
                    "ok",
                    "Routing- und Policy-Tabellen lesbar",
                    (
                        f"{len([x for x in route_output.splitlines() if x.strip()])} Route(n)",
                        f"{len([x for x in rule_output.splitlines() if x.strip()])} Policy-Regel(n)",
                    ),
                )
            )
        except Exception as exc:
            checks.append(
                HealthCheck(
                    "iproute2",
                    "Routing-Werkzeuge",
                    "error",
                    "Routing- oder Policy-Tabellen nicht lesbar",
                    (str(exc),),
                )
            )

        # Firewall tooling must be present for future OFFLINE/device policies.
        try:
            fw4 = self._ssh(
                "command -v nft >/dev/null 2>&1 && echo nft || "
                "(command -v iptables >/dev/null 2>&1 && echo iptables) || true"
            ).strip()
            if fw4:
                checks.append(
                    HealthCheck(
                        "firewall",
                        "Firewall-System",
                        "ok",
                        "Firewall-Werkzeuge verfügbar",
                        (f"Backend: {fw4}",),
                    )
                )
            else:
                checks.append(
                    HealthCheck(
                        "firewall",
                        "Firewall-System",
                        "warning",
                        "Kein unterstütztes Firewall-Werkzeug erkannt",
                        (),
                    )
                )
        except Exception as exc:
            checks.append(
                HealthCheck(
                    "firewall",
                    "Firewall-System",
                    "warning",
                    "Firewall-System konnte nicht geprüft werden",
                    (str(exc),),
                )
            )

        # WANSINN OFFLINE uses an isolated nftables table. Do not create it
        # during Medic; only verify that nft itself can manage inet tables.
        try:
            nft_ok = self._ssh(
                "command -v nft >/dev/null 2>&1 && echo OK || true"
            ).strip() == "OK"
            checks.append(
                HealthCheck(
                    "offline-capability",
                    "WANSINN OFFLINE",
                    "ok" if nft_ok else "warning",
                    (
                        "OFFLINE-Firewall verfügbar"
                        if nft_ok
                        else "OFFLINE-Firewall nicht verfügbar"
                    ),
                    (),
                )
            )
        except Exception as exc:
            checks.append(
                HealthCheck(
                    "offline-capability",
                    "WANSINN OFFLINE",
                    "warning",
                    "OFFLINE-Firewall konnte nicht geprüft werden",
                    (str(exc),),
                )
            )

        try:
            takeover = self.takeover_status()
            checks.append(
                HealthCheck(
                    "exclusive-control",
                    "Exklusive Routingkontrolle",
                    "ok" if takeover["exclusive"] else "error",
                    "GL.iNet kmwan ist gestoppt; WANSINN besitzt das Routing" if takeover["exclusive"] else "GL.iNet kmwan ist aktiv und konkurriert mit WANSINN",
                    (
                        f"kmwan enable(runtime): {takeover.get('effective_enable')}",
                        f"kmwan /proc state: {takeover.get('proc_config') or 'leer'}",
                        f"Recovery: {takeover.get('snapshot') or 'noch nicht erzeugt'}",
                    ),
                )
            )
        except Exception as exc:
            checks.append(HealthCheck("exclusive-control", "Exklusive Routingkontrolle", "error", "Exclusive-Control-Status konnte nicht geprüft werden", (str(exc),)))

        # Add-on itself is healthy when the required read paths are available.
        critical_ids = {"ssh", "uci-network", "ubus-network", "iproute2", "exclusive-control"}
        critical_bad = any(
            check.id in critical_ids and check.status == "error"
            for check in checks
        )
        checks.append(
            HealthCheck(
                "addon",
                "Router-Add-on",
                "error" if critical_bad else "ok",
                (
                    "GL.iNet/OpenWrt Add-on nicht einsatzbereit"
                    if critical_bad
                    else "GL.iNet/OpenWrt Add-on einsatzbereit"
                ),
                (),
            )
        )

        return checks

    def diagnostics(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "connection": self.test_connection(),
            "board": self._board(),
            "interfaces": {},
            "network_uci": self._ssh("uci -q show network"),
            "routes": self._ssh("ip -4 route show"),
            "rules": self._ssh("ip -4 rule show"),
            "wansinn_pbr_rules": self._ssh(
                "ip -4 rule show | awk -F: '$1 >= 19000 && $1 < 19700'"
            ),
            "wansinn_pbr_tables": {
                name: self._ssh(
                    f"ip -4 route show table {self._pbr_table_id(name)}"
                )
                for name in self._wan_sections()
            },
            "wansinn_offline_firewall": self._ssh(
                "nft list table inet wansinn 2>/dev/null || true"
            ),
            "exclusive_control": self.takeover_status(),
        }
        for name in self._wan_sections():
            result["interfaces"][name] = self._wan_state(name)
        return result
