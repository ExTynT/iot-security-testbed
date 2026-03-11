#!/usr/bin/env bash
# Generický secure štart – spustí MQTT+CoAP+OTA secure naraz.
# Pre čisté experimenty odporúča sa použiť per-scenár overlay:
#   make mqtt-secure   alebo
#   make coap-secure   alebo
#   make ota-secure
set -euo pipefail
cd "$(dirname "$0")/.."
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
