import json
from functools import lru_cache
from pathlib import Path

from flask import current_app, g
import re

SUPPORTED_LANGUAGES = {
    "de": "Deutsch",
    "en": "English",
}
DEFAULT_LANGUAGE = "de"


def _locale_root() -> Path:
    return Path(__file__).resolve().parent.parent / "locales"


@lru_cache(maxsize=16)
def _read_json(path_text: str) -> dict[str, str]:
    path = Path(path_text)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        current_app.logger.exception("i18n: locale konnte nicht geladen werden: %s", path)
        return {}
    return {str(k): str(v) for k, v in data.items()}


def get_language() -> str:
    cached = getattr(g, "wansinn_language", None)
    if cached in SUPPORTED_LANGUAGES:
        return cached

    language = DEFAULT_LANGUAGE
    try:
        from .db import get_db
        row = get_db().execute(
            "SELECT value FROM settings WHERE key='language'"
        ).fetchone()
        if row and row["value"] in SUPPORTED_LANGUAGES:
            language = row["value"]
    except Exception:
        # Setup/DB initialization must never fail because translation lookup did.
        language = DEFAULT_LANGUAGE

    g.wansinn_language = language
    return language


def set_language(language: str) -> None:
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError("Unsupported language")
    from .db import get_db
    db = get_db()
    db.execute(
        "INSERT INTO settings(key,value) VALUES('language',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (language,),
    )
    db.commit()
    g.wansinn_language = language


def _catalog(language: str) -> dict[str, str]:
    catalog = dict(_read_json(str(_locale_root() / f"{language}.json")))

    # Addons may ship locales/<lang>.json. Keys intentionally share the same
    # namespace so an addon can translate labels it contributes to the core UI.
    addon_name = str(current_app.config.get("WANSINN_ADDON", "")).strip()
    addons_dir = Path(current_app.config.get("ADDONS_DIR", ""))
    if addon_name and addons_dir:
        addon_catalog = _read_json(
            str(addons_dir / addon_name / "locales" / f"{language}.json")
        )
        catalog.update(addon_catalog)
    return catalog


def translate(key: str, default: str | None = None, **values) -> str:
    language = get_language()
    text = _catalog(language).get(key)
    if text is None:
        text = _catalog(DEFAULT_LANGUAGE).get(key, default if default is not None else key)
    try:
        return text.format(**values) if values else text
    except (KeyError, ValueError):
        current_app.logger.warning("i18n: format error for key %s", key)
        return text


# Backward-compatible public helper expected by core imports.
t = translate

# Human-readable logs are translated at the presentation boundary.
# The physical log file remains unchanged for forensic/history purposes.
_LOG_EN = {
    "ignoriere Infrastruktur-IPs": "ignoring infrastructure IPs",
    "ignoriert — reservierte WANSINN-Infrastruktur-IP": "ignored — reserved WANSINN infrastructure IP",
    "Infrastruktur-IP-Erkennung des Add-ons fehlgeschlagen": "add-on infrastructure IP detection failed",
    "lokale WANSINN-Host-IPs": "local WANSINN host IPs",
    "lokale Host-IPs konnten nicht gelesen werden": "local host IPs could not be read",
    "reservierte WANSINN-Infrastruktur-Gerät(e) entfernt": "reserved WANSINN infrastructure device(s) removed",
    "ungültige Infrastruktur-IP in Datenbank ignoriert": "invalid infrastructure IP ignored in database",
    "ungültige reservierte IP": "invalid reserved IP",
    "nicht importiert; MAC gehört bereits": "not imported; MAC already belongs to",
    "als festes Gerät übernommen": "adopted as fixed device",
    "konnte nicht übernommen werden": "could not be adopted",
    "an bestehendes Gerät": "bound to existing device",
    "gebunden": "bound",
    "zog auf": "moved to",
    "aber IP gehört bereits": "but IP already belongs to",
    "IP-Wechsel für": "IP change for",
    "Gerätesuche fehlgeschlagen": "device discovery failed",
    "Gerät konnte nicht bearbeitet werden": "device could not be edited",
    "Geräte-IP Rollback fehlgeschlagen": "device IP rollback failed",
    "Manuelle Gerätesuche fehlgeschlagen": "manual device discovery failed",
    "WAN-Umschaltung fehlgeschlagen": "WAN switch failed",
    "OFFLINE nicht durchgeführt": "OFFLINE not applied",
    "OFFLINE-Aktivierung fehlgeschlagen": "OFFLINE activation failed",
    "Routerstatus gelesen": "router status read",
    "Routerstatus übernommen": "router status applied",
    "Routen konnten nicht gelesen werden": "routes could not be read",
    "AUTO-Reconcile beim Öffnen der Routenseite fehlgeschlagen": "AUTO reconcile while opening routes page failed",
    "Routenprofil konnte nicht angelegt werden": "route profile could not be created",
    "WAN-Profil Statusänderung fehlgeschlagen": "WAN profile status change failed",
    "Routenprofil konnte nicht gelöscht werden": "route profile could not be deleted",
    "AUTO-Zustände konnten nicht gemeinsam gespeichert werden": "AUTO states could not be saved together",
    "AUTO konnte": "AUTO could not",
    "nicht auf": "to",
    "setzen": "set",
    "WAN-Healthcheck": "WAN health check",
    "technisch fehlgeschlagen": "failed technically",
    "Zeitfenster konnte nicht verschoben werden": "time window could not be moved",
    "Automation-Test fehlgeschlagen": "automation test failed",
    "Routerkonfiguration konnte nicht übernommen werden": "router configuration could not be applied",
    "Infrastruktur aktualisiert": "infrastructure updated",
    "bereits verwaltete Infrastruktur-Gerät(e) entfernt": "already managed infrastructure device(s) removed",
    "Infrastruktur konnte nicht gespeichert werden": "infrastructure could not be saved",
    "Update-Paket wurde abgelehnt": "update package was rejected",
    "WANSINN.cfg Import fehlgeschlagen": "WANSINN.cfg import failed",
    "Import abgebrochen": "import aborted",
    "Prüflauf gestartet": "check run started",
    "Prüfe SSH": "checking SSH",
    "SSH okay": "SSH OK",
    "Starte Routerchecks": "starting router checks",
    "Prüfe RouterOS": "checking RouterOS",
    "Prüfe Default-Routen": "checking default routes",
    "Prüfe Policy-Routing-Regeln": "checking policy routing rules",
    "Prüfe WAN-NAT": "checking WAN NAT",
    "Prüfe OFFLINE-Policy": "checking OFFLINE policy",
    "Prüfe Provider-Listen und Konflikte": "checking provider lists and conflicts",
    "Prüfe Datenbank ↔ Router": "checking database ↔ router",
    "Prüflauf beendet": "check run finished",
    "MikroTik health check abgeschlossen": "MikroTik health check completed",
    "Start MikroTik health check": "start MikroTik health check",
    "Keine Mehrfachzuordnungen": "no multiple assignments",
    "Konflikt(e) gefunden": "conflict(s) found",
    "Provider-Listen lesbar": "provider lists readable",
    "Unbekannte force-Listen gefunden": "unknown force lists found",
    "Masquerade-Regeln vollständig": "masquerade rules complete",
    "Masquerade-Regeln nicht vollständig erkannt": "masquerade rules not fully detected",
    "OFFLINE-Geräte vorhanden, aber Sperrregel fehlt": "OFFLINE devices exist, but blocking rule is missing",
    "OFFLINE-Sperrregel bereit": "OFFLINE blocking rule ready",
    "Bereit · Regel wird bei erster Nutzung angelegt": "ready · rule will be created on first use",
    "Interface nicht erkannt": "interface not detected",
    "Prüfung fehlgeschlagen": "check failed",
    "fehlgeschlagen": "failed",
    "übernommen": "applied",
    "gefunden": "found",
    "ignoriert": "ignored",
    "ignoriere": "ignoring",
    "keine": "none",
    "unbekannt": "unknown",
    "Benutzer": "user",
    "Gerät": "device",
    "Geräte": "devices",
}

_HEALTH_EN_EXACT = {
    "WANSINN OFFLINE": "WANSINN OFFLINE",
    "OFFLINE-Firewall verfügbar": "OFFLINE firewall available",
    "OFFLINE-Firewall nicht verfügbar": "OFFLINE firewall unavailable",
    "OFFLINE-Firewall konnte nicht geprüft werden": "OFFLINE firewall could not be checked",
    "OpenWrt-Netzwerkkonfiguration": "OpenWrt network configuration",
    "UCI-Netzwerkkonfiguration lesbar": "UCI network configuration readable",
    "UCI-Netzwerkkonfiguration nicht lesbar": "UCI network configuration not readable",
    "OpenWrt Runtime-Netzwerk": "OpenWrt runtime network",
    "ubus Netzwerkstatus verfügbar": "ubus network status available",
    "Keine ubus Netzwerk-Interfaces gefunden": "No ubus network interfaces found",
    "ubus Netzwerkstatus nicht verfügbar": "ubus network status unavailable",
    "Routing-Werkzeuge": "Routing tools",
    "Routing- und Policy-Tabellen lesbar": "Routing and policy tables readable",
    "Routing- oder Policy-Tabellen nicht lesbar": "Routing or policy tables not readable",
    "Firewall-System": "Firewall system",
    "Firewall-Werkzeuge verfügbar": "Firewall tools available",
    "Kein unterstütztes Firewall-Werkzeug erkannt": "No supported firewall tool detected",
    "Firewall-System konnte nicht geprüft werden": "Firewall system could not be checked",
    "GL.iNet/OpenWrt Add-on einsatzbereit": "GL.iNet/OpenWrt add-on ready",
    "GL.iNet/OpenWrt Add-on nicht einsatzbereit": "GL.iNet/OpenWrt add-on not ready",
    "OpenWrt / GL.iNet": "OpenWrt / GL.iNet",
    "Router erkannt": "Router detected",
    "Systeminformationen unvollständig": "System information incomplete",
    "WAN-Erkennung": "WAN detection",
    "Keine WAN-Interfaces erkannt": "No WAN interfaces detected",
    "Interface ist deaktiviert": "Interface is disabled",
    "Kein Gerät/Port zugeordnet": "No device/port assigned",
    "Interface ist UP": "Interface is UP",
    "Interface wartet auf Verbindung": "Interface is waiting for a connection",
    "Interface ist DOWN": "Interface is DOWN",
    "SSH-Verbindung": "SSH connection",
    "RouterOS": "RouterOS",
    "Router-Add-on": "Router add-on",
    "Routing-Tabellen": "Routing tables",
    "Provider-Default-Routen": "Provider default routes",
    "Policy-Routing-Regeln": "Policy routing rules",
    "WAN-NAT": "WAN NAT",
    "OFFLINE-Policy": "OFFLINE policy",
    "Provider-Listen": "Provider lists",
    "Provider-Konflikte": "Provider conflicts",
    "Router → Datenbank": "Router → database",
    "Datenbank ↔ Router": "Database ↔ router",

    "SSH-Verbindung fehlgeschlagen": "SSH connection failed",
    "SSH erreichbar": "SSH reachable",
    "SSH nicht erreichbar": "SSH not reachable",
    "SSH-Prüfung fehlgeschlagen": "SSH check failed",
    "RouterOS erreichbar": "RouterOS reachable",
    "Router hat den Diagnosebefehl abgelehnt": "Router rejected the diagnostic command",
    "Routing-Tabellen vollständig": "Routing tables complete",
    "Routing-Tabellen fehlen": "Routing tables missing",
    "Alle Provider-Routen aktiv": "All provider routes active",
    "Provider-Routen benötigen Aufmerksamkeit": "Provider routes need attention",
    "Alle Policy-Regeln vorhanden": "All policy rules present",
    "Policy-Regeln fehlen": "Policy rules missing",
    "Masquerade-Regeln vollständig": "Masquerade rules complete",
    "Masquerade-Regeln nicht vollständig erkannt": "Masquerade rules not fully detected",
    "OFFLINE-Geräte vorhanden, aber Sperrregel fehlt": "OFFLINE devices exist, but the blocking rule is missing",
    "force-offline enthält Einträge": "force-offline contains entries",
    "OFFLINE-Sperrregel bereit": "OFFLINE blocking rule ready",
    "Bereit · Regel wird bei erster Nutzung angelegt": "Ready · rule will be created on first use",
    "Provider-Listen lesbar": "Provider lists readable",
    "Unbekannte force-Listen gefunden": "Unknown force lists found",
    "Keine Mehrfachzuordnungen": "No multiple assignments",
    "Alle Router-Policies sind WANSINN bekannt": "All router policies are known to WANSINN",
    "Datenbank und Router stimmen überein": "Database and router are in sync",
    "Abweichungen zwischen Datenbank und Router": "Differences between database and router",
    "Prüfung fehlgeschlagen": "Check failed",
    "Prüfung nicht ausgeführt": "Check not run",
    "Übersprungen · SSH nicht verfügbar": "Skipped · SSH unavailable",
    "Router-Diagnose fehlgeschlagen": "Router diagnostics failed",
}

_HEALTH_EN_PREFIXES = (
    ("Interface-Sektion(en) erkannt", "interface section(s) detected"),
    ("Interface-Objekt(e)", "interface object(s)"),
    ("Route(n)", "route(s)"),
    ("Policy-Regel(n)", "policy rule(s)"),
    ("Backend:", "Backend:"),
    ("Hostname:", "Hostname:"),
    ("OpenWrt:", "OpenWrt:"),
    ("GL.iNet:", "GL.iNet:"),
    ("Kernel:", "Kernel:"),
    ("Adresse:", "Address:"),
    ("Protokoll:", "Protocol:"),
    ("Metrik:", "Metric:"),
    ("per SSH erreichbar", "reachable via SSH"),
    ("Benutzer:", "User:"),
    ("Modell:", "Model:"),
    ("Architektur:", "Architecture:"),
    ("CPU-Last:", "CPU load:"),
    ("Fehlt:", "Missing:"),
    ("Nicht aktiv:", "Inactive:"),
)

_HEALTH_EN_REGEX = (
    (re.compile(r"^(\d+) Interface-Sektion\(en\) erkannt$"), r"\1 interface section(s) detected"),
    (re.compile(r"^(\d+) Interface-Objekt\(e\)$"), r"\1 interface object(s)"),
    (re.compile(r"^(\d+) Route\(n\)$"), r"\1 route(s)"),
    (re.compile(r"^(\d+) Policy-Regel\(n\)$"), r"\1 policy rule(s)"),
    (re.compile(r"^(\d+) Gerät\(e\) synchron$"), r"\1 device(s) in sync"),
    (re.compile(r"^(\d+) Device\(e\) synchron$"), r"\1 device(s) in sync"),
    (re.compile(r"^(\d+) unbekannte Router-Policies$"), r"\1 unknown router policies"),
    (re.compile(r"^(\d+) unbekannte Router-Policy$"), r"\1 unknown router policy"),
    (re.compile(r"^(\d+) Konflikt\(e\) gefunden$"), r"\1 conflict(s) found"),
)

def translate_health_text(value: str) -> str:
    """Translate complete HealthCheck phrases without substring mutation."""
    if get_language() != "en" or not value:
        return value

    text = str(value)

    exact = _HEALTH_EN_EXACT.get(text)
    if exact is not None:
        return exact

    for source, target in _HEALTH_EN_PREFIXES:
        if text == source:
            return target
        if text.startswith(source + " "):
            return target + text[len(source):]

    for pattern, replacement in _HEALTH_EN_REGEX:
        if pattern.fullmatch(text):
            return pattern.sub(replacement, text)

    return text

def translate_log_line(line: str) -> str:
    """Translate known human-readable log fragments for the active UI language."""
    if get_language() != "en" or not line:
        return line

    translated = str(line)
    # Specific/long fragments must win over generic fragments.
    for source, target in sorted(_LOG_EN.items(), key=lambda item: len(item[0]), reverse=True):
        translated = translated.replace(source, target)

    # Clean up spacing introduced by fragments with an empty/short replacement.
    translated = re.sub(r"[ \t]{2,}", " ", translated)
    return translated

def init_app(app) -> None:
    app.jinja_env.globals["t"] = translate

    @app.context_processor
    def inject_i18n():
        language = get_language()
        return {
            "lang": language,
            "languages": SUPPORTED_LANGUAGES,
            "current_language": language,
            "supported_languages": SUPPORTED_LANGUAGES,
        }

# Runtime messages are intentionally translated at the presentation boundary.
# Internal logs stay language-neutral/historical, while flash/API messages follow
# the selected UI language. Longest fragments win so dynamic values can remain intact.
_RUNTIME_EN = {
    " aus WANSINN-Verwaltung entfernt.": " removed from WANSINN management.",
    "Profilname gespeichert: ": "Profile name saved: ",
    "Profilname nicht gespeichert: ": "Profile name not saved: ",
    "Profilname darf nicht leer sein.": "Profile name must not be empty.",
    "Profilname darf maximal 64 Zeichen lang sein.": "Profile name must be at most 64 characters long.",
    "Profilname enthält ungültige Steuerzeichen.": "Profile name contains invalid control characters.",
    "AUTO und OFFLINE sind reservierte Profilnamen.": "AUTO and OFFLINE are reserved profile names.",
    "Dieser Profilname wird bereits verwendet.": "This profile name is already in use.",
    "Bitte zuerst anmelden.": "Please sign in first.",
    "Benutzername oder Passwort ist falsch.": "Username or password is incorrect.",
    "Dieses Benutzerkonto ist deaktiviert.": "This user account is disabled.",
    "Das Passwort muss mindestens 10 Zeichen lang sein.": "The password must be at least 10 characters long.",
    "Das neue Passwort muss mindestens 10 Zeichen lang sein.": "The new password must be at least 10 characters long.",
    "Ungültige Rolle.": "Invalid role.",
    "Du kannst dein eigenes Konto nicht deaktivieren.": "You cannot disable your own account.",
    "Der letzte aktive Administrator kann nicht entfernt werden.": "The last active administrator cannot be removed.",
    "Benutzer nicht gefunden.": "User not found.",
    "Gruppenname fehlt.": "Group name is missing.",
    "Gruppe gespeichert.": "Group saved.",
    "Gruppe gelöscht. Geräte bleiben erhalten.": "Group deleted. Devices remain.",
    "Gruppe nicht gefunden.": "Group not found.",
    "Gruppe hat keine Geräte.": "Group has no devices.",
    "Ungültiges Gruppenprofil.": "Invalid group profile.",
    "Gerätename fehlt.": "Device name is missing.",
    "Gerät wurde nicht mehr in der Discovery-Liste gefunden.": "Device is no longer present in the discovery list.",
    "IP oder MAC ist bereits einem verwalteten Gerät zugeordnet.": "IP or MAC is already assigned to a managed device.",
    "IP oder MAC bereits vorhanden.": "IP or MAC already exists.",
    "Gerät fehlt.": "Device is missing.",
    "Gerät entfernt.": "Device removed.",
    "Gerät nicht gefunden.": "Device not found.",
    "Routerstatus übernommen.": "Router status applied.",
    "Routerstatus gelesen: Gerät bleibt OFFLINE.": "Router status read: device remains OFFLINE.",
    "OFFLINE nicht aktiviert: Administrator-Passwort ist falsch.": "OFFLINE not enabled: administrator password is incorrect.",
    "Profilfarbe gespeichert.": "Profile color saved.",
    "Profil nicht gefunden.": "Profile not found.",
    "Ungültiges Profil.": "Invalid profile.",
    "Ungültiges Migrationsziel.": "Invalid migration target.",
    "Ungültige Ersetzung.": "Invalid replacement.",
    "AUTO-Zustand nicht gefunden.": "AUTO state not found.",
    "AUTO-Zustand dupliziert. WAN-Kombination jetzt anpassen.": "AUTO state duplicated. Adjust the WAN combination now.",
    "AUTO-Zustand gelöscht.": "AUTO state deleted.",
    "Ein Zustand mit komplett deaktivierten WANs existiert bereits. Bitte diesen zuerst bearbeiten.": "A state with all WANs disabled already exists. Edit that state first.",
    "Mindestens einen Wochentag auswählen.": "Select at least one weekday.",
    "Zeitfenster nicht gefunden.": "Time window not found.",
    "Ungültiger Fenstertyp.": "Invalid window type.",
    "Start und Ende dürfen nicht identisch sein.": "Start and end must not be identical.",
    "Ungültiges Gerät.": "Invalid device.",
    "Ungültige Aktion.": "Invalid action.",
    "Ungültige Uhrzeit.": "Invalid time.",
    "Zeitfenster angelegt und aktueller Zustand geprüft.": "Time window created and current state checked.",
    "Zeitfenster gespeichert und aktueller Zustand geprüft.": "Time window saved and current state checked.",
    "Zeitfenster gelöscht und aktueller Zustand geprüft.": "Time window deleted and current state checked.",
    "Automation angelegt und aktueller Zustand geprüft.": "Automation created and current state checked.",
    "Automation gespeichert und aktueller Zustand geprüft.": "Automation saved and current state checked.",
    "Automation gelöscht und aktueller Zustand geprüft.": "Automation deleted and current state checked.",
    "Automation nicht gefunden.": "Automation not found.",
    "Automation testweise ausgeführt.": "Automation test executed.",
    "API-Token widerrufen. API-Zugriffe sind jetzt deaktiviert.": "API token revoked. API access is now disabled.",
    "Bitte ein WANSINN-ZIP auswählen.": "Please select a WANSINN ZIP file.",
    "Update-Paket muss eine .zip-Datei sein.": "Update package must be a .zip file.",
    "Update-Paket ist größer als 200 MB.": "Update package is larger than 200 MB.",
    "ZIP ist kein gültiges WANSINN-Update-Paket.": "ZIP is not a valid WANSINN update package.",
    "Update-ZIP enthält einen unsicheren Dateipfad.": "Update ZIP contains an unsafe file path.",
    "Update-ZIP darf keine Symlinks enthalten.": "Update ZIP must not contain symlinks.",
    "Bitte eine WANSINN.cfg auswählen.": "Please select a WANSINN.cfg file.",
    "Die Konfigurationsdatei ist zu groß.": "The configuration file is too large.",
    "Nicht unterstützte Config-Version.": "Unsupported config version.",
    "Ungültiger Importmodus.": "Invalid import mode.",
    "Ungültiger API-Token.": "Invalid API token.",
    "OFFLINE benötigt explizit confirm_offline=true.": "OFFLINE explicitly requires confirm_offline=true.",
    "Router-Add-on ist nicht geladen.": "Router add-on is not loaded.",
    "OFFLINE muss über eine autorisierte Sicherheitsaktion aktiviert werden.": "OFFLINE must be enabled through an authorized security action.",
    "AUTO ist für automatisch übernommene Router-Policies gesperrt. Das Gerät hat noch keine AUTO-Zuordnungen in der Redundanzmatrix.": "AUTO is locked for automatically adopted router policies. The device has no AUTO assignments in the redundancy matrix yet.",
    "0.0.0.0 ist kein gültiges Health-Ziel.": "0.0.0.0 is not a valid health target.",
    "Multicast-Adressen sind kein gültiges Health-Ziel.": "Multicast addresses are not valid health targets.",
    "Loopback-Adressen sind kein gültiges Health-Ziel.": "Loopback addresses are not valid health targets.",
    "Reservierte IPv4-Adressen sind kein gültiges Health-Ziel.": "Reserved IPv4 addresses are not valid health targets.",
    "Ungültige IPv4-Adresse.": "Invalid IPv4 address.",
    "Ungültige MAC-Adresse.": "Invalid MAC address.",
    "Multicast-MAC-Adressen sind nicht als Gerät zulässig.": "Multicast MAC addresses are not allowed as devices.",
    "Testing-IP ist nicht konfiguriert.": "Testing IP is not configured.",
    "WANSINN-Netzwerkhelper fehlt. Bitte ./install.sh erneut ausführen.": "WANSINN network helper is missing. Please run ./install.sh again.",
    "Testing-IP konnte nicht eingerichtet werden.": "Testing IP could not be configured.",
    "Testing-IP wurde eingerichtet, Antwort war aber ungültig.": "Testing IP was configured, but the response was invalid.",
    "SSH-Key konnte nicht erzeugt werden.": "SSH key could not be generated.",
    "SSH-Transport konnte nicht aufgebaut werden.": "SSH transport could not be established.",
    "RouterOS konnte den SSH-Key nicht importieren.": "RouterOS could not import the SSH key.",
    "SSH-Key wurde übertragen, aber der anschließende Key-Login ist fehlgeschlagen.": "SSH key was transferred, but the subsequent key login failed.",
    "Management-IP und Testing-IP müssen verschieden sein.": "Management IP and testing IP must be different.",
    "SSH-Port ist ungültig.": "SSH port is invalid.",
    "Router-Benutzername ist ungültig.": "Router username is invalid.",
    "Dieses Setup unterstützt aktuell nur MikroTik.": "This setup currently supports MikroTik only.",
    "SSH-Passwort fehlt.": "SSH password is missing.",
    "Admin-Passwort muss mindestens 10 Zeichen lang sein.": "Administrator password must be at least 10 characters long.",
    "Admin-Passwörter stimmen nicht überein.": "Administrator passwords do not match.",
    "Router-Verbindung konnte nicht bestätigt werden.": "Router connection could not be confirmed.",
    "Einrichtung abgeschlossen. SSH-Passwort wurde nicht gespeichert.": "Setup complete. SSH password was not stored.",
    "Einrichtung fehlgeschlagen: ": "Setup failed: ",
    "Gruppe nicht angelegt: ": "Group not created: ",
    "Gruppe nicht gespeichert: ": "Group not saved: ",
    "Gerätesuche fehlgeschlagen: ": "Device search failed: ",
    "Gerät nicht gespeichert: ": "Device not saved: ",
    "Umschalten fehlgeschlagen: ": "Switch failed: ",
    "OFFLINE fehlgeschlagen: ": "OFFLINE failed: ",
    "Sync fehlgeschlagen: ": "Sync failed: ",
    "Löschen fehlgeschlagen: ": "Delete failed: ",
    "Routen konnten nicht gelesen werden: ": "Routes could not be read: ",
    "Routenprofil nicht angelegt: ": "Route profile not created: ",
    "Farbe konnte nicht gespeichert werden: ": "Color could not be saved: ",
    "Healthcheck nicht gespeichert: ": "Health check not saved: ",
    "Test fehlgeschlagen: ": "Test failed: ",
    "Profilstatus nicht geändert: ": "Profile status not changed: ",
    "Migration fehlgeschlagen: ": "Migration failed: ",
    "Profil nicht gelöscht: ": "Profile not deleted: ",
    "AUTO-Zustände nicht gespeichert: ": "AUTO states not saved: ",
    "AUTO konnte nicht angewendet werden: ": "AUTO could not be applied: ",
    "Zeitfenster nicht angelegt: ": "Time window not created: ",
    "Zeitfenster nicht gespeichert: ": "Time window not saved: ",
    "Zeitfenster nicht gelöscht: ": "Time window not deleted: ",
    "Automation nicht angelegt: ": "Automation not created: ",
    "Automation nicht gespeichert: ": "Automation not saved: ",
    "Automation fehlgeschlagen: ": "Automation failed: ",
    "Infrastruktur nicht gespeichert: ": "Infrastructure not saved: ",
    "Update nicht gestartet: ": "Update not started: ",
    "Import fehlgeschlagen: ": "Import failed: ",
    "Importdaten sind ungültig oder abgelaufen: ": "Import data is invalid or expired: ",
    "Import abgebrochen: ": "Import aborted: ",
    " gespeichert.": " saved.",
    " angelegt.": " created.",
    " hinzugefügt.": " added.",
    " aktiviert.": " enabled.",
    " deaktiviert.": " disabled.",
    " wurde gelöscht.": " was deleted.",
    "Gerät ": "Device ",
    "Geräte": "devices",
    "Gruppe ": "Group ",
    "Profil ": "Profile ",
    "Prüfung fehlgeschlagen": "Check failed",
    "Nicht ausgeführt": "Not run",
    "Übersprungen": "Skipped",
    "Verbindung": "Connection",
    "Routing-Tabellen": "Routing tables",
    "Default-Routen": "Default routes",
    "Provider-Listen": "Provider lists",
    "Provider-Konflikte": "Provider conflicts",
    "Datenbank": "Database",
    "Profilname enthält keine zulässigen Zeichen.": "Profile name contains no valid characters.",
    "Profilname ist zu lang.": "Profile name is too long.",
    "Dieser Profilname ist reserviert.": "This profile name is reserved.",
    "Die Router-Liste 'internal-networks' fehlt. WANSINN legt keine PBR-Regel ohne diese Schutzgrenze an.": "The router list 'internal-networks' is missing. WANSINN does not create a PBR rule without this safety boundary.",
    "Unbekanntes Profil": "Unknown profile",
    "Profil wurde auf dem Router nicht gefunden.": "Profile was not found on the router.",
    "Profil wurde angelegt, aber von WANSINN nicht wiedererkannt.": "Profile was created but not recognized by WANSINN afterwards.",
    "Passende Mangle-Regel ist nicht eindeutig WANSINN zugeordnet.": "Matching mangle rule is not uniquely assigned to WANSINN.",
    "Profil ist nach dem Löschen weiterhin vorhanden.": "Profile still exists after deletion.",
    "SSH-Verbindung fehlgeschlagen": "SSH connection failed",
    "RouterOS-Fehler": "RouterOS error",
    "OFFLINE-Sperrregel konnte auf dem Router nicht verifiziert werden.": "OFFLINE blocking rule could not be verified on the router.",
    "OFFLINE wurde gesetzt, aber die Sperre konnte nicht vollständig verifiziert werden.": "OFFLINE was set, but the block could not be fully verified.",
    "Gerät steht in mehreren Provider-Listen": "Device is present in multiple provider lists",
    "SSH-Verbindung": "SSH connection",
    "Router-Add-on": "Router add-on",
    "Router hat den Diagnosebefehl abgelehnt": "Router rejected the diagnostic command",
    "Routing-Tabellen vollständig": "Routing tables complete",
    "Routing-Tabellen fehlen": "Routing tables missing",
    "Routing-Tabellen": "Routing tables",
    "Provider-Default-Routen": "Provider default routes",
    "Alle Provider-Routen aktiv": "All provider routes active",
    "Provider-Routen benötigen Aufmerksamkeit": "Provider routes need attention",
    "Policy-Routing-Regeln": "Policy routing rules",
    "Alle Policy-Regeln vorhanden": "All policy rules present",
    "Policy-Regeln fehlen": "Policy rules missing",
    "Masquerade-Regeln vollständig": "Masquerade rules complete",
    "Masquerade-Regeln nicht vollständig erkannt": "Masquerade rules not fully detected",
    "OFFLINE-Geräte vorhanden, aber Sperrregel fehlt": "OFFLINE devices exist, but the blocking rule is missing",
    "force-offline enthält Einträge": "force-offline contains entries",
    "OFFLINE-Sperrregel bereit": "OFFLINE blocking rule ready",
    "Bereit · Regel wird bei erster Nutzung angelegt": "Ready · rule will be created on first use",
    "Provider-Listen lesbar": "Provider lists readable",
    "Unbekannte force-Listen gefunden": "Unknown force lists found",
    "Keine Mehrfachzuordnungen": "No multiple assignments",
    "Alle Router-Policies sind WANSINN bekannt": "All router policies are known to WANSINN",
    "Router → Datenbank": "Router → database",
    "Prüfung fehlgeschlagen": "Check failed",
    "unbekannt": "unknown",
    "geladen": "loaded",
    "per SSH erreichbar": "reachable via SSH",
    "Benutzer:": "User:",
    "Modell:": "Model:",
    "Architektur:": "Architecture:",
    "CPU-Last:": "CPU load:",
    "Fehlt:": "Missing:",
    "Nicht aktiv:": "Inactive:",
    "Interface nicht erkannt": "Interface not detected",
    "unbekannte Router-Policy": "unknown router policy",
    "unbekannte Router-Policies": "unknown router policies",
    "Konflikt(e) gefunden": "conflict(s) found",
}


def translate_text(text: str) -> str:
    """Translate a user-facing runtime message without modifying stored/raw logs."""
    if not isinstance(text, str) or get_language() == DEFAULT_LANGUAGE:
        return text
    # Prefer explicit locale values first.
    de_catalog = _catalog(DEFAULT_LANGUAGE)
    en_catalog = _catalog(get_language())
    reverse = {v: en_catalog.get(k, v) for k, v in de_catalog.items()}
    if text in reverse:
        return reverse[text]
    if text in _RUNTIME_EN:
        return _RUNTIME_EN[text]
    result = text
    for source, target in sorted(_RUNTIME_EN.items(), key=lambda item: len(item[0]), reverse=True):
        if source in result:
            result = result.replace(source, target)
    return result


def flash_i18n(message, category="message"):
    from flask import flash
    return flash(translate_text(str(message)), category)


def _translate_payload(value, key=None):
    translatable_keys = {"error", "message", "label", "detail", "warning"}
    if isinstance(value, dict):
        return {k: _translate_payload(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_translate_payload(v, key) for v in value]
    if isinstance(value, str) and key in translatable_keys:
        return translate_text(value)
    return value


def jsonify_i18n(*args, **kwargs):
    from flask import jsonify
    if args and len(args) == 1 and isinstance(args[0], (dict, list)):
        args = (_translate_payload(args[0]),)
    if kwargs:
        kwargs = _translate_payload(kwargs)
    return jsonify(*args, **kwargs)
