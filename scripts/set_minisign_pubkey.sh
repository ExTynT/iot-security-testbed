#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f configs/ota/minisign.pub ]; then
  echo "Chyba: configs/ota/minisign.pub neexistuje" >&2
  exit 1
fi

echo "MINISIGN_PUBKEY sa uz nezapisuje do .env."
echo "OTA secure profil cita verejny kluc priamo z configs/ota/minisign.pub."
