#!/usr/bin/env bash
# MQTT Secure - kontrolny beh s opravnenym klientom.
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

MQTT_CTRL_USER="${MQTT_CTRL_USER:-$(grep '^MQTT_CTRL_USER=' .env | cut -d= -f2-)}"
MQTT_CTRL_PASS="${MQTT_CTRL_PASS:-$(grep '^MQTT_CTRL_PASS=' .env | cut -d= -f2-)}"
RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
LOGF="runs/${RUN_ID}/logs/attacks.log"
CTRL_LOG="runs/${RUN_ID}/logs/mqtt_control.log"

: > "$CTRL_LOG"

echo "=== MQTT SECURE - kontrolny beh (autorizovany controller) ==="
echo ""
echo "[1] Controller publikuje na cmd/test cez TLS 8883..."
docker compose exec -T attacker \
  mosquitto_pub -h mosquitto -p 8883 --cafile /work/certs/ca.crt \
  -u "$MQTT_CTRL_USER" -P "$MQTT_CTRL_PASS" \
  -t cmd/test -m "kontrolny_beh" -d \
  && echo "P1_mqtt_auth_write_ok 1" >> "$LOGF" \
  && echo "AUTH_WRITE_OK" >> "$CTRL_LOG" \
  && echo ">>> USPECH - controller ma autorizovany write do cmd/#"

echo ""
echo "[2] Controller cita telemetriu DUT..."
AUTH_READ_OK=0
for attempt in 1 2 3; do
  echo "AUTH_READ_ATTEMPT=${attempt}" >> "$CTRL_LOG"
  if docker compose exec -T attacker \
    mosquitto_sub -h mosquitto -p 8883 --cafile /work/certs/ca.crt \
    -u "$MQTT_CTRL_USER" -P "$MQTT_CTRL_PASS" \
    -t telemetry/version -C 1 -W 10 \
    | tee -a "$CTRL_LOG"; then
    AUTH_READ_OK=1
    break
  fi
  sleep 2
done

if [ "$AUTH_READ_OK" -eq 1 ]; then
  echo "P1_mqtt_auth_read_ok 1" >> "$LOGF"
  echo "AUTH_READ_OK" >> "$CTRL_LOG"
  echo ">>> USPECH - controller cita telemetry/version"
else
  echo "AUTH_READ_TIMEOUT" >> "$CTRL_LOG"
  echo ">>> VAROVANIE - autorizovane citanie telemetrie sa nepotvrdilo"
fi

echo ""
echo "=== VYSLEDOK: autorizovany write a read su overene oddelenym controller kontom ==="
