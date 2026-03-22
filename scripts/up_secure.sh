#!/usr/bin/env bash
# Generic secure start for all overlays.
# For reproducible thesis scenarios prefer Makefile targets or scripts/_run_all.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f configs/ota/minisign.pub ]; then
  bash scripts/set_minisign_pubkey.sh
else
  echo "Upozornenie: configs/ota/minisign.pub neexistuje, OTA secure nebude plne aktivne." >&2
fi

docker compose \
  -f docker-compose.yml \
  -f docker-compose.mqtt-secure.yml \
  -f docker-compose.coap-secure.yml \
  -f docker-compose.ota-secure.yml \
  build
docker compose \
  -f docker-compose.yml \
  -f docker-compose.mqtt-secure.yml \
  -f docker-compose.coap-secure.yml \
  -f docker-compose.ota-secure.yml \
  up -d
