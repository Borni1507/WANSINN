#!/usr/bin/env bash
set -euo pipefail
pkill -f "[w]aitress-serve.*run:app" 2>/dev/null || true
pkill -f "[p]ython run.py" 2>/dev/null || true
echo "WANSINN wurde gestoppt."
