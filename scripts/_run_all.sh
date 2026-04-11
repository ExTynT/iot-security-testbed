#!/usr/bin/env bash
# Spustí všetky scenáre sekvenčne bez GNU Make.
# Používa rovnaký workflow ako Makefile: new_run -> wait_ready -> attack/control -> collector -> down.
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

BASE="-f docker-compose.yml"
MQTT_S="-f docker-compose.yml -f docker-compose.mqtt-secure.yml"
COAP_S="-f docker-compose.yml -f docker-compose.coap-secure.yml"
OTA_S="-f docker-compose.yml -f docker-compose.ota-secure.yml"
MINISIGN_BIN="${MINISIGN_BIN:-minisign}"

REPLICATIONS=${1:-3}

run_collector() {
  docker compose run --rm --build monitor-collector
}

ensure_ota_keys() {
  command -v "$MINISIGN_BIN" >/dev/null 2>&1 || {
    echo "minisign not found; set MINISIGN_BIN or install minisign" >&2
    exit 1
  }
  if [ ! -f configs/ota/minisign.pub ]; then
    printf '\n\n' | "$MINISIGN_BIN" \
      -G -p configs/ota/minisign.pub -s configs/ota/minisign.key
  fi
  printf '\n' | "$MINISIGN_BIN" \
    -S -s configs/ota/minisign.key -m configs/ota/repo/manifest.json >/dev/null
}

write_compose_files_state() {
  local run_id="$1"
  local compose_args="$2"

  printf '%s\n' "$compose_args" | grep -oE 'docker-compose[^[:space:]]+\.yml' \
    > "runs/${run_id}/state/compose_files.txt"
}

run_case() {
  local name="$1"
  local compose_args="$2"
  shift 2
  cleanup() { docker compose $compose_args down --remove-orphans || true; }
  trap cleanup EXIT

  bash scripts/new_run.sh
  RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
  echo "$name" > "runs/${RUN_ID}/state/scenario.txt"
  write_compose_files_state "$RUN_ID" "$compose_args"

  docker compose $compose_args up -d --wait --wait-timeout 90
  bash "scripts/wait_ready.sh" "$name"

  for script in "$@"; do
    bash "$script"
  done

  run_collector
  trap - EXIT
  cleanup
}

echo ""
echo "========================================"
echo "  IoT Security Testbed - Replikacie"
echo "  Pocet replikacii: ${REPLICATIONS}"
echo "========================================"

for rep in $(seq 1 "${REPLICATIONS}"); do
  echo ""
  echo "========== MQTT BASELINE [${rep}/${REPLICATIONS}] =========="
  run_case "mqtt-baseline" "$BASE" "scripts/mqtt_baseline_attack.sh"

  echo ""
  echo "========== MQTT SECURE [${rep}/${REPLICATIONS}] =========="
  run_case "mqtt-secure" "$MQTT_S" \
    "scripts/mqtt_secure_attack_unauth.sh" \
    "scripts/mqtt_secure_control_auth.sh"

  echo ""
  echo "========== COAP BASELINE [${rep}/${REPLICATIONS}] =========="
  run_case "coap-baseline" "$BASE" "scripts/coap_baseline_attack.sh"

  echo ""
  echo "========== COAP SECURE [${rep}/${REPLICATIONS}] =========="
  run_case "coap-secure" "$COAP_S" \
    "scripts/coap_secure_attack_plain_should_fail.sh" \
    "scripts/coap_secure_attack_wrong_psk.sh" \
    "scripts/coap_secure_attack_ok_psk.sh"

  echo ""
  echo "========== OTA BASELINE [${rep}/${REPLICATIONS}] =========="
  run_case "ota-baseline" "$BASE" "scripts/ota_attack_evil.sh"

  echo ""
  echo "========== OTA SECURE [${rep}/${REPLICATIONS}] =========="
  ensure_ota_keys
  cleanup() { docker compose $OTA_S down --remove-orphans || true; }
  trap cleanup EXIT
  bash scripts/new_run.sh
  RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
  echo "ota-secure" > "runs/${RUN_ID}/state/scenario.txt"
  write_compose_files_state "$RUN_ID" "$OTA_S"
  docker compose $OTA_S up -d --wait --wait-timeout 90
  bash scripts/wait_ready.sh ota-secure
  bash scripts/ota_secure_control_signed.sh
  bash scripts/ota_attack_evil.sh
  run_collector
  trap - EXIT
  cleanup
done

echo ""
echo "========================================"
echo "  VSETKY SCENARE DOKONCENE"
echo "  ${REPLICATIONS} replikacii x 6 scenarov = $((REPLICATIONS * 6)) behov"
echo "========================================"
