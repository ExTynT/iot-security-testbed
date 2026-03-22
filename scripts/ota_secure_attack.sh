#!/usr/bin/env bash
# Compatibility wrapper for the old secure OTA attack helper.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[INFO] scripts/ota_secure_attack.sh je legacy wrapper."
echo "[INFO] Pre plny secure scenar najprv spusti scripts/ota_secure_control_signed.sh a potom scripts/ota_attack_evil.sh."
exec bash scripts/ota_attack_evil.sh
