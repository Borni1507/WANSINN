# WANSINN Add-on API

Ein Router-Add-on liegt unter `addons/<id>/` und enthält mindestens:

- `manifest.json`
- `plugin.py`

`manifest.json` definiert Identität, Version, Entrypoint und Capabilities. Der Entrypoint implementiert `wansinn.core.contracts.RouterAddon`.

## Pflichtinterface

Jedes Add-on implementiert:

- `profiles() -> list[WanProfile]`
- `test_connection() -> dict`
- `set_device_profile(ip, profile) -> None`
- `get_device_profile(ip) -> str`
- `diagnostics() -> dict`
- `health_check() -> list[HealthCheck]`

## Optionale Hooks

Der Core erkennt zusätzliche Hooks per Capability/`hasattr`, darunter:

- `managed_profiles()` – Router-WAN-Profile für WANSINN
- `probe_profile(profile_id, target, timeout)` – WAN-Probe über den Router
- `profile_availability()` – read-only WAN-Verfügbarkeit
- `apply_effective_profile(ip, profile)` – bereits aufgelöstes AUTO-Ziel anwenden
- `discover_devices()` – routerseitige Client-Beobachtungen liefern
- `discovery_infrastructure_ips()` – Router-/Management-Adressen vom Device-Discovery ausschließen
- `router_device_policies()` – bestehende Router-Policies zur Adoption lesen
- `take_control()` – konkurrierende Routersteuerung übernehmen
- `ensure_control()` – Exclusive-Control nach Reboot/Drift erneut herstellen
- `takeover_status()` – Status der Routerübernahme liefern
- `create_route_profile(...)` / `delete_route_profile(...)` – falls das Backend Routerprofile verwalten kann

## Discovery-Vertrag

`discover_devices()` liefert Beobachtungen, nicht die endgültige WANSINN-Geräteliste. Typische Felder sind:

```python
{
    "mac": "AA:BB:CC:DD:EE:01",
    "ip": "192.168.50.20",
    "name": "Example-Client",
    "interface": "br-lan",
    "source": "dhcp"
}
```

Der Core übernimmt Deduplizierung, Infrastrukturfilter, Identity-Merge und Adoption. Das Add-on soll VLAN-/LAN-Sicht des Routers nutzen und keine WAN-Nachbarn als Clients melden.

## Exclusive-Control-Vertrag

Wenn ein Hersteller bereits eine konkurrierende Multi-WAN-Engine besitzt, darf WANSINN nur dann exklusive Routinggarantien geben, wenn das Add-on diese Engine kontrolliert deaktivieren und den Zustand verifizieren kann.

Persistente Eingriffe müssen vorab reversibel dokumentiert werden. Das GL.iNet-Backend nutzt dafür einen nicht persistenten `kmwan`-Takeover plus Change-Snapshot und Bash-Recovery-Script.

## Grundregel

**Router-spezifische Befehle gehören nie in den WANSINN-Core.**

Der Core entscheidet *was* passieren soll. Das aktive Add-on weiß *wie* der jeweilige Router diese Entscheidung umsetzt.
