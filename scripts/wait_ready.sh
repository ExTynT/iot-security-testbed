#!/usr/bin/env bash
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

SCENARIO="${1:-}"
RUN_ID="$(grep '^RUN_ID=' .env | cut -d= -f2)"
MQTT_CTRL_USER="${MQTT_CTRL_USER:-$(grep '^MQTT_CTRL_USER=' .env | cut -d= -f2-)}"
MQTT_CTRL_PASS="${MQTT_CTRL_PASS:-$(grep '^MQTT_CTRL_PASS=' .env | cut -d= -f2-)}"

retry_until() {
  local label="$1"
  local max_attempts="$2"
  shift 2

  for attempt in $(seq 1 "$max_attempts"); do
    if "$@"; then
      echo "READY: $label"
      return 0
    fi
    sleep 1
  done

  echo "TIMEOUT: $label" >&2
  return 1
}

case "$SCENARIO" in
  mqtt-baseline)
    retry_until "MQTT baseline broker" 30 \
      docker compose exec -T attacker \
      mosquitto_pub -h mosquitto -p 1883 -t telemetry/ready -m "probe" >/dev/null 2>&1
    ;;
  mqtt-secure)
    retry_until "MQTT secure broker" 30 \
      docker compose exec -T attacker \
      mosquitto_pub -h mosquitto -p 8883 --cafile /work/certs/ca.crt \
      -u "$MQTT_CTRL_USER" -P "$MQTT_CTRL_PASS" \
      -t cmd/ready -m "probe" >/dev/null 2>&1
    retry_until "DUT MQTT connection" 30 \
      grep -q "MQTT connected rc=" "runs/${RUN_ID}/logs/dut.log"
    ;;
  coap-baseline)
    retry_until "CoAP baseline server" 30 \
      docker compose exec -T attacker \
      coap-client -m get coap://coap/.well-known/core >/dev/null 2>&1
    ;;
  coap-secure)
    retry_until "CoAP secure firewall activation" 30 \
      grep -q "CoAP DTLS PSK: 5683=BLOCKED 5684=DTLS+PSK" "runs/${RUN_ID}/logs/coap.log"
    ;;
  ota-baseline|ota-secure)
    retry_until "OTA official server" 30 \
      docker compose exec -T attacker curl -fsS http://ota/manifest.json >/dev/null 2>&1
    retry_until "OTA evil server" 30 \
      docker compose exec -T attacker curl -fsS http://ota_evil/manifest.json >/dev/null 2>&1
    retry_until "DUT MQTT connection" 30 \
      grep -q "MQTT connected rc=" "runs/${RUN_ID}/logs/dut.log"
    ;;
  *)
    echo "Pouzitie: $0 <mqtt-baseline|mqtt-secure|coap-baseline|coap-secure|ota-baseline|ota-secure>" >&2
    exit 1
    ;;
esac
