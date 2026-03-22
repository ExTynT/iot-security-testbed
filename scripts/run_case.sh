#!/usr/bin/env bash
# Spusti jeden scenar bez GNU Make, rovnakym workflow ako Makefile.
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

BASE="-f docker-compose.yml"
MQTT_S="-f docker-compose.yml -f docker-compose.mqtt-secure.yml"
COAP_S="-f docker-compose.yml -f docker-compose.coap-secure.yml"
OTA_S="-f docker-compose.yml -f docker-compose.ota-secure.yml"

usage() {
  cat <<'EOF'
Pouzitie:
  bash scripts/run_case.sh <scenario>

Podporovane scenare:
  mqtt-baseline
  mqtt-secure
  coap-baseline
  coap-secure
  ota-baseline
  ota-secure
EOF
}

ensure_mqtt_passwd() {
  if [ ! -f configs/mqtt/secure/passwd ]; then
    bash scripts/gen_mqtt_passwd.sh
  fi
}

ensure_ota_keys() {
  if [ ! -f configs/ota/minisign.pub ]; then
    printf '\n\n' | tools/minisign/minisign-win64/minisign.exe \
      -G -p configs/ota/minisign.pub -s configs/ota/minisign.key
  fi
  if [ ! -f configs/ota/repo/manifest.json.minisig ]; then
    printf '\n' | tools/minisign/minisign-win64/minisign.exe \
      -S -s configs/ota/minisign.key -m configs/ota/repo/manifest.json
  fi
}

run_collector() {
  docker compose run --rm monitor-collector
}

run_common_case() {
  local scenario="$1"
  local compose_args="$2"
  shift 2

  bash scripts/new_run.sh
  local run_id
  run_id="$(grep '^RUN_ID=' .env | cut -d= -f2)"
  echo "$scenario" > "runs/${run_id}/state/scenario.txt"

  docker compose $compose_args up -d
  bash scripts/wait_ready.sh "$scenario"

  for script in "$@"; do
    bash "$script"
  done

  run_collector
  docker compose $compose_args down --remove-orphans
}

if [ $# -ne 1 ]; then
  usage
  exit 1
fi

case "$1" in
  mqtt-baseline)
    run_common_case "mqtt-baseline" "$BASE" "scripts/mqtt_baseline_attack.sh"
    ;;
  mqtt-secure)
    ensure_mqtt_passwd
    run_common_case "mqtt-secure" "$MQTT_S" \
      "scripts/mqtt_secure_attack_unauth.sh" \
      "scripts/mqtt_secure_control_auth.sh"
    ;;
  coap-baseline)
    run_common_case "coap-baseline" "$BASE" "scripts/coap_baseline_attack.sh"
    ;;
  coap-secure)
    run_common_case "coap-secure" "$COAP_S" \
      "scripts/coap_secure_attack_plain_should_fail.sh" \
      "scripts/coap_secure_attack_wrong_psk.sh" \
      "scripts/coap_secure_attack_ok_psk.sh"
    ;;
  ota-baseline)
    run_common_case "ota-baseline" "$BASE" "scripts/ota_attack_evil.sh"
    ;;
  ota-secure)
    ensure_ota_keys
    bash scripts/new_run.sh
    run_id="$(grep '^RUN_ID=' .env | cut -d= -f2)"
    echo "ota-secure" > "runs/${run_id}/state/scenario.txt"
    bash scripts/set_minisign_pubkey.sh
    docker compose $OTA_S up -d
    bash scripts/wait_ready.sh ota-secure
    docker compose $OTA_S up -d --force-recreate dut
    bash scripts/wait_ready.sh ota-secure
    bash scripts/ota_secure_control_signed.sh
    bash scripts/ota_attack_evil.sh
    run_collector
    docker compose $OTA_S down --remove-orphans
    ;;
  *)
    usage
    exit 1
    ;;
esac

echo "Scenar '$1' dokonceny."
