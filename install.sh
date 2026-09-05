#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
VERSION="$(tr -d '[:space:]' < VERSION 2>/dev/null || echo unknown)"
echo
echo "======================================"
echo "   WANSINN v${VERSION} Installer"
echo "======================================"
echo
if [ "${EUID:-$(id -u)}" -eq 0 ]; then
  echo "Bitte Installer nicht direkt mit sudo starten. Nutze ./install.sh"
  exit 1
fi
command -v python3 >/dev/null || { echo "Python 3 fehlt."; exit 1; }
command -v ssh >/dev/null || { echo "OpenSSH Client fehlt."; exit 1; }
command -v ip >/dev/null || { echo "iproute2 fehlt."; exit 1; }
command -v ping >/dev/null || { echo "iputils-ping fehlt."; exit 1; }
command -v traceroute >/dev/null || { echo "traceroute fehlt."; exit 1; }

if [ ! -d .venv ]; then
  echo "[1/5] Erstelle Python-Umgebung ..."
  python3 -m venv .venv || { echo "Bitte python3-venv installieren."; exit 1; }
else
  echo "[1/5] Python-Umgebung vorhanden."
fi

echo "[2/5] Installiere Python-Abhängigkeiten ..."
.venv/bin/python -m ensurepip --upgrade >/dev/null 2>&1 || true
.venv/bin/python -m pip install --upgrade pip >/dev/null
.venv/bin/python -m pip install -r requirements.txt

echo "[3/5] Installiere lokalen Netzwerkhelper ..."
echo "Dafür wird einmal dein sudo-Passwort benötigt."
sudo install -o root -g root -m 0755 wansinn-net-helper /usr/local/sbin/wansinn-net-helper
USER_NAME="$(id -un)"
echo "${USER_NAME} ALL=(root) NOPASSWD: /usr/local/sbin/wansinn-net-helper *" | \
  sudo tee /etc/sudoers.d/wansinn >/dev/null
sudo chmod 0440 /etc/sudoers.d/wansinn

echo "[4/5] Richte Traceroute-Netzwerkrechte ein ..."
command -v setcap >/dev/null || {
  echo "setcap fehlt. Bitte das Paket libcap2-bin installieren."
  exit 1
}
TRACEROUTE_BIN="$(readlink -f "$(command -v traceroute)")"
sudo setcap cap_net_raw+ep "${TRACEROUTE_BIN}"
if command -v getcap >/dev/null; then
  TRACEROUTE_CAPS="$(getcap "${TRACEROUTE_BIN}" 2>/dev/null || true)"
  if [[ "${TRACEROUTE_CAPS}" != *"cap_net_raw"* ]]; then
    echo "Traceroute-Netzwerkrecht konnte nicht gesetzt werden."
    echo "Bitte ./install.sh erneut ausführen."
    exit 1
  fi
fi

echo "[5/5] Fertig."
echo
echo "Jetzt nur noch:"
echo "  ./start.sh"
echo
echo "Die restliche Einrichtung läuft im Browser."
