#!/usr/bin/env bash
# Kompatibilitný presmerovací skript pre historický názov.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[INFO] scripts/coap_secure_attack_ok.sh je historický wrapper."
echo "[INFO] Presmerovávam na scripts/coap_secure_attack_ok_psk.sh."
exec bash scripts/coap_secure_attack_ok_psk.sh
