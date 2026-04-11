#!/usr/bin/env bash
# Kompatibilitný presmerovací skript pre starý helper OTA secure útoku.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[INFO] scripts/ota_secure_attack.sh je historický wrapper."
echo "[INFO] Pre plný secure scenár najprv spusti scripts/ota_secure_control_signed.sh a potom scripts/ota_attack_evil.sh."
exec bash scripts/ota_attack_evil.sh
