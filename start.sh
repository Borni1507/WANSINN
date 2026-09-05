#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
VERSION="$(tr -d '[:space:]' < VERSION 2>/dev/null || echo unknown)"

if [ ! -x ".venv/bin/python" ]; then
  echo "Bitte zuerst ./install.sh ausführen."
  exit 1
fi

if [ -f ".env" ]; then
  set -a
  source .env
  set +a
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
IP="${IP:-127.0.0.1}"

if ss -ltnH 'sport = :8080' 2>/dev/null | grep -q .; then
  echo
  printf '\033[1;31m'
  echo '-----------------'
  echo '|  PORT BELEGT  |'
  echo '-----------------'
  printf '\033[0m'
  echo
  exit 1
fi

echo
echo "======================================"
echo "   WANSINN v${VERSION} startet"
echo "======================================"
echo
echo "Browser: http://${IP}:8080"
if [ ! -f ".env" ]; then
  echo "Status:  Erstinstallation — Browser-Assistent wartet"
fi
echo "Beenden mit STRG+C"
echo

exec .venv/bin/waitress-serve --host=0.0.0.0 --port=8080 run:app
