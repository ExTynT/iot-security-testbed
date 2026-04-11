#!/usr/bin/env bash
# Historický alias ponechaný kvôli spätnej kompatibilite.
# Kanonický skript je ota_attack_evil.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

exec bash scripts/ota_attack_evil.sh
