from __future__ import annotations

import ipaddress
import re
import subprocess
import threading
import time
from collections import defaultdict
from pathlib import Path

from wansinn.core.contracts import AddonInfo, HealthCheck, RouterAddon, WanProfile
from wansinn.core.db import get_db
from wansinn.core.validation import validate_mac, validate_private_ipv4


import logging
log = logging.getLogger(__name__)

class MikroTikError(RuntimeError):
    pass


class MikroTikAddon(RouterAddon):
    def __init__(self, app, manifest):
        self.app = app
        self.host = app.config["MIKROTIK_HOST"]
        self.user = app.config["MIKROTIK_USER"]
        self.key = app.config["MIKROTIK_SSH_KEY"]
        self.port = app.config["MIKROTIK_PORT"]
        self.known_hosts = app.config["MIKROTIK_KNOWN_HOSTS"]
        # RouterOS is perfectly capable of serving several SSH sessions, but
        # WANSINN may otherwise create a burst of discovery/health/AUTO calls
        # during a router replacement.  Serialize CLI access and cache the
        # static profile schema briefly so every device switch does not need
        # another full mangle-table discovery.
        self._ssh_lock = threading.RLock()
        self._profile_cache_lock = threading.RLock()
        self._profile_cache: dict[str, dict[str, str]] = {}
        self._profile_cache_at = 0.0
        self._profile_cache_ttl = 2.0
        self.info = AddonInfo(
            manifest["id"],
            manifest["name"],
            manifest["vendor"],
            manifest["version"],
            manifest.get("description", ""),
            tuple(manifest.get("capabilities", [])),
        )

    def _invalidate_profile_cache(self) -> None:
        with self._profile_cache_lock:
            self._profile_cache = {}
            self._profile_cache_at = 0.0

    def _discover_profiles(self, *, force: bool = False) -> dict[str, dict[str, str]]:
        """Discover WANSINN PBR profiles from RouterOS mangle rules.

        Profile definitions change only when a WAN profile is created/deleted.
        Device switching used to re-read the complete mangle table for every
        single client.  During large AUTO reconciles this produced a storm of
        SSH sessions and a transient empty discovery could turn an otherwise
        valid target into ``Unbekanntes Profil``.  Keep a very short cache and
        explicitly invalidate it on profile lifecycle changes.
        """
        now = time.monotonic()
        with self._profile_cache_lock:
            if (
                not force
                and self._profile_cache
                and now - self._profile_cache_at < self._profile_cache_ttl
            ):
                return {key: dict(value) for key, value in self._profile_cache.items()}

        output = self._ssh('/ip firewall mangle print terse')
        discovered: dict[str, dict[str, str]] = {}
        for line in output.splitlines():
            if "action=mark-routing" not in line:
                continue
            address_list = self._extract_value(line, "src-address-list")
            table = self._extract_value(line, "new-routing-mark")
            if not address_list or not address_list.startswith("force-"):
                continue
            if address_list == "force-offline" or not table:
                continue

            profile_id = address_list[len("force-"):].strip().lower()
            if not profile_id:
                continue
            discovered[profile_id] = {
                "list": address_list,
                "table": table,
                "label": profile_id.replace("-", " ").upper(),
            }

        # Never replace a known-good cache with a transient empty read.  An
        # actually empty router is handled correctly on first discovery, while
        # lifecycle operations invalidate the cache explicitly.
        with self._profile_cache_lock:
            if discovered or not self._profile_cache:
                self._profile_cache = {key: dict(value) for key, value in discovered.items()}
                self._profile_cache_at = time.monotonic()
            return {key: dict(value) for key, value in self._profile_cache.items()}

    def _profiles_for_switch(self, profile: str) -> dict[str, dict[str, str]]:
        """Return a stable profile map and retry discovery once on a miss."""
        discovered = self._discover_profiles()
        if profile in {"auto", "offline"} or profile in discovered:
            return discovered

        # A cache miss may mean a profile was just created or RouterOS returned
        # a transiently incomplete CLI snapshot.  One forced refresh is enough
        # to distinguish that from a genuinely unknown profile.
        discovered = self._discover_profiles(force=True)
        if profile not in discovered:
            log.error(
                "MikroTik: Profil %r nicht gefunden; Router meldet Profile: %s",
                profile, ", ".join(sorted(discovered)) or "<keine>",
            )
        return discovered

    @staticmethod
    def _profile_slug(name: str) -> str:
        slug = name.strip().lower()
        slug = re.sub(r"[^a-z0-9-]+", "-", slug)
        slug = re.sub(r"-{2,}", "-", slug).strip("-")
        if not slug:
            raise ValueError("Profilname enthält keine zulässigen Zeichen.")
        if len(slug) > 32:
            raise ValueError("Profilname ist zu lang.")
        if slug in {"auto", "offline"}:
            raise ValueError("Dieser Profilname ist reserviert.")
        return slug

    def managed_profiles(self) -> list[dict[str, str]]:
        """Return currently discovered PBR profiles with their default gateways."""
        discovered = self._discover_profiles()
        route_output = self._ssh(
            '/ip route print terse where dst-address=0.0.0.0/0'
        )

        profiles: list[dict[str, str]] = []
        for profile_id, data in sorted(discovered.items()):
            gateway = ""
            for line in route_output.splitlines():
                if f"routing-table={data['table']}" not in line:
                    continue
                gateway = self._extract_value(line, "gateway") or ""
                if gateway:
                    break

            profiles.append(
                {
                    "id": profile_id,
                    "label": data["label"],
                    "list": data["list"],
                    "table": data["table"],
                    "gateway": gateway,
                }
            )
        return profiles


    def _ensure_internal_networks(self, profile_gateway: str) -> None:
        """Ensure the RouterOS ``internal-networks`` safety boundary exists.

        Existing lists are treated as administrator-owned and are never
        rewritten.  On a fresh RouterOS installation WANSINN creates the list
        from connected IPv4 networks while excluding networks/interfaces used
        by default routes and the gateway of the profile currently being
        created.  This keeps PBR from hijacking traffic to local LAN/VLAN/VPN
        networks without requiring a pre-existing WANSINN RouterOS setup.
        """
        existing = self._ssh(
            '/ip firewall address-list print terse where list="internal-networks"'
        )
        if existing.strip():
            return

        address_output = self._ssh('/ip address print terse')
        default_routes = self._ssh(
            '/ip route print terse where dst-address=0.0.0.0/0'
        )

        external_gateways: set[ipaddress.IPv4Address] = set()
        external_interfaces: set[str] = set()

        try:
            external_gateways.add(ipaddress.IPv4Address(profile_gateway))
        except ipaddress.AddressValueError:
            pass

        for line in default_routes.splitlines():
            for key in ("gateway", "immediate-gw"):
                value = self._extract_value(line, key)
                if not value:
                    continue

                # RouterOS may expose values such as 192.0.2.1%ether1.
                gateway_part, _, iface_part = value.partition("%")
                if iface_part:
                    external_interfaces.add(iface_part)

                try:
                    external_gateways.add(ipaddress.IPv4Address(gateway_part))
                except ipaddress.AddressValueError:
                    # PPP/tunnel default routes can use the interface itself
                    # as the gateway value.  Treat that interface as external.
                    if gateway_part:
                        external_interfaces.add(gateway_part)

        internal_networks: set[ipaddress.IPv4Network] = set()
        for line in address_output.splitlines():
            address = self._extract_value(line, "address")
            interface = self._extract_value(line, "interface") or ""
            if not address:
                continue

            try:
                network = ipaddress.IPv4Interface(address).network
            except (ipaddress.AddressValueError, ValueError):
                continue

            if (
                network.network_address.is_loopback
                or network.network_address.is_link_local
                or network.network_address.is_multicast
                or network.network_address.is_unspecified
            ):
                continue
            if interface and interface in external_interfaces:
                continue
            if any(gateway in network for gateway in external_gateways):
                continue

            internal_networks.add(network)

        if not internal_networks:
            raise MikroTikError(
                "Die Router-Liste 'internal-networks' fehlt und WANSINN konnte "
                "kein internes IPv4-Netz sicher automatisch erkennen. "
                "Bitte LAN/VLAN-Konfiguration des Routers prüfen."
            )

        for network in sorted(internal_networks, key=lambda n: (int(n.network_address), n.prefixlen)):
            cidr = str(network)
            self._ssh(
                f'/ip firewall address-list add list="internal-networks" '
                f'address="{cidr}" comment="WANSINN: auto-detected internal network"'
            )

        verify = self._ssh(
            '/ip firewall address-list print terse where list="internal-networks"'
        )
        if not verify.strip():
            raise MikroTikError(
                "WANSINN konnte die Router-Liste 'internal-networks' nicht anlegen."
            )

        log.warning(
            "MikroTik: internal-networks automatisch angelegt: %s",
            ", ".join(str(network) for network in sorted(
                internal_networks, key=lambda n: (int(n.network_address), n.prefixlen)
            )),
        )

    def create_route_profile(self, name: str, gateway: str) -> dict[str, str]:
        """Create only the WANSINN-owned Layer-3 PBR objects.

        This deliberately does not configure interfaces, VLANs, DHCP or NAT.
        Existing conflicting objects are never overwritten.
        """
        gateway = validate_private_ipv4(gateway)
        profile_id = self._profile_slug(name)
        label = name.strip()[:48] or profile_id.upper()
        address_list = f"force-{profile_id}"
        table = f"via-{profile_id}"

        # WANSINN's PBR rules intentionally exclude internal destinations.
        # Fresh RouterOS installations do not necessarily have the protection
        # list yet, so bootstrap it from locally connected non-WAN networks.
        self._ensure_internal_networks(gateway)

        table_output = self._ssh('/routing table print terse')
        table_lines = [
            line
            for line in table_output.splitlines()
            if f"name={table}" in line
        ]
        if table_lines and not any("fib" in line for line in table_lines):
            raise MikroTikError(
                f"Routing-Tabelle {table} existiert, ist aber nicht als FIB-Tabelle nutzbar."
            )

        route_output = self._ssh(
            '/ip route print terse where dst-address=0.0.0.0/0'
        )
        matching_routes = [
            line
            for line in route_output.splitlines()
            if f"routing-table={table}" in line
        ]
        if matching_routes:
            existing_gateways = {
                self._extract_value(line, "gateway")
                for line in matching_routes
            }
            existing_gateways.discard(None)
            if existing_gateways != {gateway}:
                existing = ", ".join(sorted(existing_gateways)) or "unbekannt"
                raise MikroTikError(
                    f"Konflikt: {table} existiert bereits mit Gateway {existing}."
                )

        mangle_output = self._ssh('/ip firewall mangle print terse')
        matching_mangle = [
            line
            for line in mangle_output.splitlines()
            if f"src-address-list={address_list}" in line
            or f"new-routing-mark={table}" in line
        ]
        if matching_mangle:
            valid = any(
                "chain=prerouting" in line
                and "action=mark-routing" in line
                and f"src-address-list={address_list}" in line
                and f"new-routing-mark={table}" in line
                and "dst-address-list=!internal-networks" in line
                for line in matching_mangle
            )
            if not valid:
                raise MikroTikError(
                    f"Konflikt: bestehende Policy für {address_list}/{table} "
                    "entspricht nicht dem WANSINN-Schema."
                )

        # Create only what is missing. Every step is immediately read back.
        if not table_lines:
            self._ssh(
                f'/routing table add fib name="{table}" '
                f'comment="WANSINN: {label}"'
            )
            verify_table = self._ssh(
                f'/routing table print terse where name="{table}"'
            )
            if f"name={table}" not in verify_table:
                raise MikroTikError(
                    f"Routing-Tabelle {table} konnte nicht verifiziert werden."
                )

        if not matching_routes:
            self._ssh(
                f'/ip route add dst-address=0.0.0.0/0 '
                f'routing-table="{table}" gateway="{gateway}" distance=1 '
                f'comment="WANSINN: {label} default"'
            )
            verify_route = self._ssh(
                '/ip route print terse where dst-address=0.0.0.0/0'
            )
            route_ok = any(
                f"routing-table={table}" in line
                and f"gateway={gateway}" in line
                for line in verify_route.splitlines()
            )
            if not route_ok:
                raise MikroTikError(
                    f"Default-Route für {table} konnte nicht verifiziert werden."
                )

        if not matching_mangle:
            self._ssh(
                f'/ip firewall mangle add chain=prerouting '
                f'action=mark-routing new-routing-mark="{table}" '
                f'passthrough=no dst-address-type=!local '
                f'src-address-list="{address_list}" '
                f'dst-address-list=!internal-networks '
                f'comment="WANSINN: {label}"'
            )
            verify_mangle = self._ssh('/ip firewall mangle print terse')
            mangle_ok = any(
                "chain=prerouting" in line
                and "action=mark-routing" in line
                and f"src-address-list={address_list}" in line
                and f"new-routing-mark={table}" in line
                and "dst-address-list=!internal-networks" in line
                for line in verify_mangle.splitlines()
            )
            if not mangle_ok:
                raise MikroTikError(
                    f"Policy-Routing-Regel für {profile_id} konnte nicht verifiziert werden."
                )

        # Final discovery through the same mechanism used by the dashboard.
        self._invalidate_profile_cache()
        discovered = self._discover_profiles(force=True)
        if profile_id not in discovered:
            raise MikroTikError(
                "Profil wurde angelegt, aber von WANSINN nicht wiedererkannt."
            )

        return {
            "id": profile_id,
            "label": label,
            "gateway": gateway,
            "table": table,
            "list": address_list,
        }

    def probe_profile(self, profile_id: str, target: str, timeout: int = 2) -> bool:
        raise NotImplementedError("WAN-Probes laufen lokal in WANSINN.")

    def profile_availability(self) -> dict[str, bool]:
        definitions = self._discover_profiles()
        route_output = self._ssh('/ip route print terse where dst-address=0.0.0.0/0')
        result = {}
        for profile_id, data in definitions.items():
            lines = [
                line for line in route_output.splitlines()
                if f"routing-table={data['table']}" in line
            ]
            result[profile_id] = any(
                line.startswith("A")
                or " A" in f" {line}"
                or "active=true" in line
                for line in lines
            )
        return result

    def apply_effective_profile(self, ip: str, profile: str) -> None:
        if profile in {"auto", "offline"}:
            self.set_device_profile(ip, profile)
            return

        discovered = self._profiles_for_switch(profile)
        if profile not in discovered:
            raise ValueError("Unbekanntes Profil")

        ip = validate_private_ipv4(ip)
        all_lists = [data["list"] for data in discovered.values()] + ["force-offline"]
        commands = [f':local ip "{ip}"']
        commands.extend(
            f'/ip firewall address-list remove [find list="{address_list}" address=$ip]'
            for address_list in all_lists
        )
        commands.append(
            f'/ip firewall address-list add list="{discovered[profile]["list"]}" '
            f'address=$ip comment="WANSINN AUTO"'
        )
        commands.append(
            '/ip firewall connection remove [find src-address~("^" . $ip . ":")]'
        )
        self._ssh("; ".join(commands))

    def delete_route_profile(self, profile_id: str) -> None:
        profile_id = self._profile_slug(profile_id)
        discovered = self._discover_profiles(force=True)
        data = discovered.get(profile_id)
        if data is None:
            raise MikroTikError("Profil wurde auf dem Router nicht gefunden.")

        address_list = data["list"]
        table = data["table"]
        assigned = self._ssh(
            f'/ip firewall address-list print terse where list="{address_list}"'
        )
        if assigned.strip():
            raise MikroTikError(
                f"{address_list} enthält noch Geräte. Profil kann nicht gelöscht werden."
            )

        mangle = self._ssh('/ip firewall mangle print terse')
        matching = [
            line for line in mangle.splitlines()
            if f"src-address-list={address_list}" in line
            and f"new-routing-mark={table}" in line
        ]
        if matching and not all("WANSINN:" in line for line in matching):
            raise MikroTikError(
                "Passende Mangle-Regel ist nicht eindeutig WANSINN zugeordnet."
            )

        self._ssh(
            f'/ip firewall mangle remove '
            f'[find src-address-list="{address_list}" new-routing-mark="{table}"]'
        )
        self._ssh(
            f'/ip route remove [find dst-address="0.0.0.0/0" routing-table="{table}"]'
        )
        self._ssh(f'/routing table remove [find name="{table}"]')

        self._invalidate_profile_cache()
        if profile_id in self._discover_profiles(force=True):
            raise MikroTikError("Profil ist nach dem Löschen weiterhin vorhanden.")

    def profiles(self):
        profiles = [WanProfile("auto", "AUTO")]
        for profile_id, data in sorted(self._discover_profiles().items()):
            profiles.append(WanProfile(profile_id, data["label"]))
        profiles.append(WanProfile("offline", "OFFLINE"))
        return profiles

    def _ssh(self, command: str, timeout: int = 10) -> str:
        if not Path(self.key).exists():
            raise MikroTikError(f"SSH-Key fehlt: {self.key}")

        try:
            with self._ssh_lock:
                result = subprocess.run(
                    [
                        "ssh",
                        "-i", self.key,
                        "-p", str(self.port),
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
            raise MikroTikError(f"SSH-Verbindung fehlgeschlagen: {exc}") from exc

        if result.returncode:
            raise MikroTikError((result.stderr or result.stdout).strip() or "RouterOS-Fehler")
        return result.stdout.strip()

    def test_connection(self):
        return {
            "ok": "WANSINN_OK" in self._ssh(':put "WANSINN_OK"'),
            "host": self.host,
            "user": self.user,
        }

    def _ensure_offline_rule(self) -> None:
        """Create and verify the WANSINN OFFLINE rule."""
        existing = self._ssh(
            '/ip firewall filter print terse where comment="WANSINN: OFFLINE"'
        )
        if existing.strip():
            return

        # Keep provisioning deliberately simple. RouterOS accepted this exact
        # rule during the live integration test.
        self._ssh(
            '/ip firewall filter add '
            'chain=forward '
            'src-address-list=force-offline '
            'dst-address-list=!internal-networks '
            'action=drop '
            'comment="WANSINN: OFFLINE"'
        )

        verified = self._ssh(
            '/ip firewall filter print terse where comment="WANSINN: OFFLINE"'
        )

        valid = any(
            'chain=forward' in line
            and 'action=drop' in line
            and 'src-address-list=force-offline' in line
            and 'dst-address-list=!internal-networks' in line
            for line in verified.splitlines()
        )

        if not valid:
            raise RuntimeError(
                "OFFLINE-Sperrregel konnte auf dem Router nicht verifiziert werden."
            )

    def set_device_profile(self, ip, profile):
        ip = validate_private_ipv4(ip)
        discovered = self._profiles_for_switch(profile)
        valid_profiles = {"auto", "offline", *discovered.keys()}
        if profile not in valid_profiles:
            raise ValueError("Unbekanntes Profil")

        if profile == "offline":
            self._ensure_offline_rule()

        all_lists = [data["list"] for data in discovered.values()] + ["force-offline"]
        commands = [f':local ip "{ip}"'] + [
            f'/ip firewall address-list remove [find list="{address_list}" address=$ip]'
            for address_list in all_lists
        ]

        target_list = (
            "force-offline"
            if profile == "offline"
            else discovered.get(profile, {}).get("list")
        )
        if target_list:
            commands.append(
                f'/ip firewall address-list add list="{target_list}" '
                f'address=$ip comment="WANSINN"'
            )
        # Bestehende Sessions müssen weg, sonst kann eine bereits etablierte
        # Verbindung trotz neuer Policy bis zu ihrem Timeout weiterleben.
        commands.append(
            '/ip firewall connection remove [find src-address~("^" . $ip . ":")]'
        )
        self._ssh("; ".join(commands))

        if profile == "offline":
            list_state = self._ssh(
                f'/ip firewall address-list print terse '
                f'where list="force-offline" and address="{ip}"'
            )
            rule_state = self._ssh(
                '/ip firewall filter print terse '
                'where comment="WANSINN: OFFLINE"'
            )

            rule_valid = any(
                'chain=forward' in line
                and 'action=drop' in line
                and 'src-address-list=force-offline' in line
                and 'dst-address-list=!internal-networks' in line
                for line in rule_state.splitlines()
            )

            if not list_state.strip() or not rule_valid:
                raise RuntimeError(
                    "OFFLINE wurde gesetzt, aber die Sperre konnte nicht "
                    "vollständig verifiziert werden."
                )

    def get_device_profile(self, ip):
        ip = validate_private_ipv4(ip)
        output = self._ssh(
            f'/ip firewall address-list print terse where address="{ip}" and list~"force-"'
        )
        discovered = self._discover_profiles()
        list_to_profile = {
            data["list"]: profile
            for profile, data in discovered.items()
        }
        list_to_profile["force-offline"] = "offline"

        found = []
        for line in output.splitlines():
            address_list = self._extract_value(line, "list")
            profile = list_to_profile.get(address_list)
            if profile:
                found.append(profile)

        if len(set(found)) > 1:
            raise MikroTikError("Gerät steht in mehreren Provider-Listen")
        return found[0] if found else "auto"

    @staticmethod
    def _extract_value(text: str, key: str) -> str | None:
        """Read RouterOS values from both terse and normal print output."""
        terse_match = re.search(
            rf'(?:^|\s){re.escape(key)}=("[^"]*"|\S+)',
            text,
        )
        if terse_match:
            return terse_match.group(1).strip('"')

        normal_match = re.search(
            rf'(?m)^\s*{re.escape(key)}\s*:\s*(.*?)\s*$',
            text,
        )
        if normal_match:
            return normal_match.group(1).strip()

        return None

    def _enabled_provider_ids(self) -> set[str]:
        return set(self._discover_profiles())

    def _profile_definitions(self) -> dict[str, dict[str, str]]:
        return self._discover_profiles()

    def _route_interface(self, route_output: str, table: str) -> str | None:
        for line in route_output.splitlines():
            if f"routing-table={table}" not in line:
                continue
            immediate = self._extract_value(line, "immediate-gw")
            if immediate and "%" in immediate:
                return immediate.rsplit("%", 1)[-1]
        return None

    def discovery_infrastructure_ips(self) -> set[str]:
        """IPs that belong to WAN infrastructure and must never be offered as clients.

        Read RouterOS directly so discovery does not depend on whether the
        local route-profile metadata has already been synchronized.
        """
        ignored: set[str] = set()

        try:
            routes = self._ssh(
                '/ip route print terse where dst-address="0.0.0.0/0"'
            )
        except Exception:
            routes = ""

        for line in routes.splitlines():
            table = self._extract_value(line, "routing-table") or ""
            gateway = self._extract_value(line, "gateway") or ""

            # WANSINN provider tables use via-*. We deliberately do not exclude
            # the main-table default gateway purely from this rule because a
            # router may contain unrelated/default infrastructure.
            if not table.startswith("via-"):
                continue

            # RouterOS can print gateway forms such as 192.168.0.1 or
            # 192.168.0.1%vlan20-kabel. Keep only the IP part.
            gateway_ip = gateway.split("%", 1)[0].strip()
            try:
                gateway_ip = validate_private_ipv4(gateway_ip)
            except ValueError:
                continue
            ignored.add(gateway_ip)

        return ignored

    def discover_devices(self) -> list[dict[str, str]]:
        """Return clients known to RouterOS, merged primarily by MAC address.

        DHCP leases provide the best name information; ARP fills in devices
        that are present without a DHCP lease.
        """
        by_mac: dict[str, dict[str, str]] = {}

        try:
            lease_output = self._ssh(
                '/ip dhcp-server lease print terse '
                'where mac-address!="" and address!=""'
            )
        except Exception:
            lease_output = ""

        for line in lease_output.splitlines():
            mac_raw = self._extract_value(line, "mac-address")
            ip_raw = self._extract_value(line, "address")
            if not mac_raw or not ip_raw:
                continue
            try:
                mac = validate_mac(mac_raw)
                ip = validate_private_ipv4(ip_raw)
            except ValueError:
                continue

            hostname = (
                self._extract_value(line, "host-name")
                or self._extract_value(line, "comment")
                or ""
            ).strip()
            status = (self._extract_value(line, "status") or "").strip()

            by_mac[mac] = {
                "mac": mac,
                "ip": ip,
                "name": hostname[:80],
                "source": "dhcp",
                "interface": "",
                "status": status,
            }

        try:
            arp_output = self._ssh(
                '/ip arp print terse where mac-address!="" and address!=""'
            )
        except Exception:
            arp_output = ""

        for line in arp_output.splitlines():
            mac_raw = self._extract_value(line, "mac-address")
            ip_raw = self._extract_value(line, "address")
            if not mac_raw or not ip_raw:
                continue
            try:
                mac = validate_mac(mac_raw)
                ip = validate_private_ipv4(ip_raw)
            except ValueError:
                continue

            interface = (self._extract_value(line, "interface") or "").strip()
            current = by_mac.get(mac)
            if current is None:
                by_mac[mac] = {
                    "mac": mac,
                    "ip": ip,
                    "name": "",
                    "source": "arp",
                    "interface": interface[:80],
                    "status": "",
                }
            else:
                # Keep the DHCP lease as the primary address/name. ARP adds
                # router-side liveness/interface context without making one
                # multi-address MAC flap between identities. The shared core
                # remains responsible for device identity on every backend.
                current["interface"] = interface[:80]
                current["source"] = "dhcp+arp"

        return sorted(
            by_mac.values(),
            key=lambda item: (
                item.get("name", "").lower(),
                item["ip"],
                item["mac"],
            ),
        )

    def router_device_policies(self) -> dict[str, str | None]:
        """Return RouterOS force-* assignments as IP -> logical profile.

        A value of None means the IP appears in multiple known policy lists and
        must not be auto-imported.
        """
        provider_defs = self._discover_profiles()
        list_to_profile = {
            data["list"]: profile_id
            for profile_id, data in provider_defs.items()
        }
        list_to_profile["force-offline"] = "offline"

        output = self._ssh(
            '/ip firewall address-list print terse where list~"force-"'
        )
        by_address: dict[str, set[str]] = defaultdict(set)

        for line in output.splitlines():
            address = self._extract_value(line, "address")
            address_list = self._extract_value(line, "list")
            profile = list_to_profile.get(address_list)
            if not address or not profile:
                continue
            try:
                address = validate_private_ipv4(address)
            except ValueError:
                continue
            by_address[address].add(profile)

        return {
            address: (next(iter(profiles)) if len(profiles) == 1 else None)
            for address, profiles in by_address.items()
        }

    def health_check(self):
        log.info("MEDIC: Start MikroTik health check")
        checks: list[HealthCheck] = []

        try:
            self.test_connection()
        except Exception as exc:
            return [
                HealthCheck(
                    "ssh",
                    "SSH-Verbindung",
                    "error",
                    "SSH-Verbindung fehlgeschlagen",
                    (str(exc),),
                ),
                HealthCheck(
                    "addon",
                    "Router-Add-on",
                    "ok",
                    f"{self.info.name} v{self.info.version} geladen",
                ),
            ]

        checks.append(
            HealthCheck(
                "ssh",
                "SSH-Verbindung",
                "ok",
                f"{self.host} per SSH erreichbar",
                (f"Host: {self.host}", f"Benutzer: {self.user}"),
            )
        )

        try:
            log.info("MEDIC: Prüfe RouterOS")
            resource = self._ssh('/system resource print')
            identity = self._ssh('/system identity print')
            version = self._extract_value(resource, "version") or "unbekannt"
            router_name = self._extract_value(identity, "name") or self.host
            board_name = self._extract_value(resource, "board-name")
            architecture = self._extract_value(resource, "architecture-name")
            cpu_load = self._extract_value(resource, "cpu-load")

            details = tuple(
                detail
                for detail in (
                    f"Modell: {board_name}" if board_name else None,
                    f"Architektur: {architecture}" if architecture else None,
                    f"CPU-Last: {cpu_load}" if cpu_load else None,
                )
                if detail
            )

            checks.append(
                HealthCheck(
                    "routeros",
                    "RouterOS",
                    "ok" if version != "unbekannt" else "warning",
                    f"{router_name} · RouterOS {version}",
                    details,
                )
            )
        except Exception as exc:
            checks.append(
                HealthCheck(
                    "routeros",
                    "RouterOS-Diagnose",
                    "error",
                    "Router hat den Diagnosebefehl abgelehnt",
                    (str(exc),),
                )
            )
        checks.append(
            HealthCheck(
                "addon",
                "Router-Add-on",
                "ok",
                f"{self.info.name} v{self.info.version} geladen",
                tuple(self.info.capabilities),
            )
        )

        provider_defs = self._profile_definitions()
        providers = set(provider_defs)

        try:
            table_output = self._ssh('/routing table print terse')
            missing_tables = [
                provider_defs[p]["table"]
                for p in sorted(providers)
                if f"name={provider_defs[p]['table']}" not in table_output
            ]
            checks.append(
                HealthCheck(
                    "routing-tables",
                    "Routing-Tabellen",
                    "error" if missing_tables else "ok",
                    "Routing-Tabellen vollständig" if not missing_tables else "Routing-Tabellen fehlen",
                    tuple(missing_tables),
                )
            )
        except Exception as exc:
            checks.append(HealthCheck("routing-tables", "Routing-Tabellen", "unknown", "Prüfung fehlgeschlagen", (str(exc),)))

        route_output = ""
        try:
            log.info("MEDIC: Prüfe Default-Routen")
            route_output = self._ssh('/ip route print terse where dst-address=0.0.0.0/0')
            missing_routes = []
            inactive_routes = []
            for provider in sorted(providers):
                table = provider_defs[provider]["table"]
                lines = [line for line in route_output.splitlines() if f"routing-table={table}" in line]
                if not lines:
                    missing_routes.append(table)
                elif not any(" A" in f" {line}" or line.startswith("A") or "active=true" in line for line in lines):
                    inactive_routes.append(table)
            status = "error" if missing_routes else ("warning" if inactive_routes else "ok")
            details = tuple([f"Fehlt: {x}" for x in missing_routes] + [f"Nicht aktiv: {x}" for x in inactive_routes])
            checks.append(
                HealthCheck(
                    "default-routes",
                    "Provider-Default-Routen",
                    status,
                    "Alle Provider-Routen aktiv" if status == "ok" else "Provider-Routen benötigen Aufmerksamkeit",
                    details,
                )
            )
        except Exception as exc:
            checks.append(HealthCheck("default-routes", "Provider-Default-Routen", "unknown", "Prüfung fehlgeschlagen", (str(exc),)))

        try:
            log.info("MEDIC: Prüfe Policy-Routing-Regeln")
            mangle_output = self._ssh('/ip firewall mangle print terse')
            missing_mangle = []
            for provider in sorted(providers):
                address_list = provider_defs[provider]["list"]
                table = provider_defs[provider]["table"]
                if not any(
                    f"src-address-list={address_list}" in line and f"new-routing-mark={table}" in line
                    for line in mangle_output.splitlines()
                ):
                    missing_mangle.append(f"{address_list} → {table}")
            checks.append(
                HealthCheck(
                    "mangle",
                    "Policy-Routing-Regeln",
                    "error" if missing_mangle else "ok",
                    "Alle Policy-Regeln vorhanden" if not missing_mangle else "Policy-Regeln fehlen",
                    tuple(missing_mangle),
                )
            )
        except Exception as exc:
            checks.append(HealthCheck("mangle", "Policy-Routing-Regeln", "unknown", "Prüfung fehlgeschlagen", (str(exc),)))

        try:
            log.info("MEDIC: Prüfe WAN-NAT")
            nat_output = self._ssh('/ip firewall nat print terse where chain=srcnat')
            route_output_for_nat = route_output or self._ssh(
                '/ip route print terse where dst-address=0.0.0.0/0'
            )
            missing_nat = []
            for provider in sorted(providers):
                table = provider_defs[provider]["table"]
                interface = self._route_interface(route_output_for_nat, table)
                if interface is None:
                    missing_nat.append(f"{provider_defs[provider]['label']}: Interface nicht erkannt")
                    continue
                if not any(
                    f"out-interface={interface}" in line and "action=masquerade" in line
                    for line in nat_output.splitlines()
                ):
                    missing_nat.append(interface)
            checks.append(
                HealthCheck(
                    "nat",
                    "WAN-NAT",
                    "warning" if missing_nat else "ok",
                    "Masquerade-Regeln vollständig" if not missing_nat else "Masquerade-Regeln nicht vollständig erkannt",
                    tuple(missing_nat),
                )
            )
        except Exception as exc:
            checks.append(HealthCheck("nat", "WAN-NAT", "unknown", "Prüfung fehlgeschlagen", (str(exc),)))

        try:
            log.info("MEDIC: Prüfe OFFLINE-Policy")
            offline_entries = self._ssh(
                '/ip firewall address-list print terse where list="force-offline"'
            )
            filter_output = self._ssh('/ip firewall filter print terse')
            offline_rule_present = any(
                'chain=forward' in line
                and 'src-address-list=force-offline' in line
                and 'action=drop' in line
                and 'dst-address-list=!internal-networks' in line
                for line in filter_output.splitlines()
            )

            if offline_entries and not offline_rule_present:
                checks.append(
                    HealthCheck(
                        "offline-policy",
                        "OFFLINE-Policy",
                        "error",
                        "OFFLINE-Geräte vorhanden, aber Sperrregel fehlt",
                        ("force-offline enthält Einträge",),
                    )
                )
            elif offline_rule_present:
                checks.append(
                    HealthCheck(
                        "offline-policy",
                        "OFFLINE-Policy",
                        "ok",
                        "OFFLINE-Sperrregel bereit",
                    )
                )
            else:
                checks.append(
                    HealthCheck(
                        "offline-policy",
                        "OFFLINE-Policy",
                        "ok",
                        "Bereit · Regel wird bei erster Nutzung angelegt",
                    )
                )
        except Exception as exc:
            checks.append(
                HealthCheck(
                    "offline-policy",
                    "OFFLINE-Policy",
                    "unknown",
                    "Prüfung fehlgeschlagen",
                    (str(exc),),
                )
            )

        try:
            log.info("MEDIC: Prüfe Provider-Listen und Konflikte")
            list_output = self._ssh('/ip firewall address-list print terse where list~"force-"')
            by_address: dict[str, set[str]] = defaultdict(set)
            known_lists = {
                data["list"] for data in provider_defs.values()
            } | {"force-offline"}
            unknown_lists = set()
            for line in list_output.splitlines():
                address = self._extract_value(line, "address")
                address_list = self._extract_value(line, "list")
                if address_list and address_list.startswith("force-") and address_list not in known_lists:
                    unknown_lists.add(address_list)
                if address and address_list in known_lists:
                    by_address[address].add(address_list)

            conflicts = [
                f"{address}: {', '.join(sorted(lists))}"
                for address, lists in sorted(by_address.items())
                if len(lists) > 1
            ]
            checks.append(
                HealthCheck(
                    "provider-lists",
                    "Provider-Listen",
                    "warning" if unknown_lists else "ok",
                    "Provider-Listen lesbar" if not unknown_lists else "Unbekannte force-Listen gefunden",
                    tuple(sorted(unknown_lists)),
                )
            )
            checks.append(
                HealthCheck(
                    "conflicts",
                    "Provider-Konflikte",
                    "error" if conflicts else "ok",
                    "Keine Mehrfachzuordnungen" if not conflicts else f"{len(conflicts)} Konflikt(e) gefunden",
                    tuple(conflicts),
                )
            )

            db = get_db()
            database_rows = db.execute(
                "SELECT ip FROM devices"
            ).fetchall()
            known_device_ips = {
                str(row["ip"])
                for row in database_rows
            }

            # WANSINN infrastructure may intentionally carry force-* policy
            # entries on RouterOS (especially the local testing interface).
            # Those addresses are not client devices and must not make Medic
            # report an unknown Router -> Database policy.
            reserved_ips = {
                str(row["ip"])
                for row in db.execute(
                    "SELECT ip FROM infrastructure_addresses"
                ).fetchall()
            }
            reserved_ips.update(
                ip for ip in (
                    str(self.app.config.get("WANSINN_MANAGEMENT_IP", "")).strip(),
                    str(self.app.config.get("WANSINN_TESTING_IP", "")).strip(),
                )
                if ip
            )

            unknown_router_policies = [
                f"{address} → {', '.join(sorted(provider_lists))}"
                for address, provider_lists in sorted(by_address.items())
                if address not in known_device_ips and address not in reserved_ips
            ]
            unknown_router_conflicts = [
                address
                for address, provider_lists in sorted(by_address.items())
                if address not in known_device_ips
                and address not in reserved_ips
                and len(provider_lists) > 1
            ]

            if unknown_router_policies:
                status = "error" if unknown_router_conflicts else "warning"
                policy_count = len(unknown_router_policies)
                message = (
                    "1 unbekannte Router-Policy"
                    if policy_count == 1
                    else f"{policy_count} unbekannte Router-Policies"
                )
                checks.append(
                    HealthCheck(
                        "router-to-database",
                        "Router → Datenbank",
                        status,
                        message,
                        tuple(unknown_router_policies),
                    )
                )
            else:
                checks.append(
                    HealthCheck(
                        "router-to-database",
                        "Router → Datenbank",
                        "ok",
                        "Alle Router-Policies sind WANSINN bekannt",
                    )
                )
        except Exception as exc:
            checks.append(HealthCheck("provider-lists", "Provider-Listen", "unknown", "Prüfung fehlgeschlagen", (str(exc),)))
            checks.append(HealthCheck("conflicts", "Provider-Konflikte", "unknown", "Prüfung fehlgeschlagen", (str(exc),)))
            checks.append(HealthCheck("router-to-database", "Router → Datenbank", "unknown", "Prüfung fehlgeschlagen", (str(exc),)))

        log.info("MEDIC: MikroTik health check abgeschlossen (%s Checks)", len(checks))
        return checks
    def diagnostics(self):
        resource = self._ssh('/system resource print')
        identity = self._ssh('/system identity print')
        return {
            "connection": self.test_connection(),
            "system": (resource.splitlines() + identity.splitlines()),
            "routing_tables": self._ssh('/routing table print terse').splitlines(),
            "routes": self._ssh('/ip route print terse where dst-address=0.0.0.0/0').splitlines(),
            "nat_rules": self._ssh('/ip firewall nat print terse where chain=srcnat').splitlines(),
            "mangle_rules": self._ssh('/ip firewall mangle print terse').splitlines(),
            "filter_rules": self._ssh('/ip firewall filter print terse').splitlines(),
            "address_lists": self._ssh('/ip firewall address-list print terse where list~"force-"').splitlines(),
        }
