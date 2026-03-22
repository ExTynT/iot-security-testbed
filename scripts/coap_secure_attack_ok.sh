#!/usr/bin/env bash
# Compatibility wrapper for the old script name.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[INFO] scripts/coap_secure_attack_ok.sh je legacy wrapper."
echo "[INFO] Presmerovavam na scripts/coap_secure_attack_ok_psk.sh."
exec bash scripts/coap_secure_attack_ok_psk.sh
