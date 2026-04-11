#!/usr/bin/env bash
# Všeobecné spustenie všetkých secure overlayov naraz.
# Pre reprodukovateľné thesis scenáre preferuj Makefile targety alebo scripts/_run_all.sh.
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
