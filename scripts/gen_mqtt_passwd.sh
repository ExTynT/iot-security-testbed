#!/usr/bin/env bash
# Vygeneruje configs/mqtt/secure/passwd pomocou Mosquitto passwd utility v Dockeri.
# Spusti RAZ pred prvým použitím docker-compose.mqtt-secure.yml.
set -euo pipefail
cd "$(dirname "$0")/.."

PASSWD_FILE="configs/mqtt/secure/passwd"
MQTT_USER="${MQTT_USER:-device01}"
MQTT_PASS="${MQTT_PASS:-device01pass}"

echo "Generujem $PASSWD_FILE pre user=$MQTT_USER ..."

docker run --rm eclipse-mosquitto:2.0.18 \
  sh -c "mosquitto_passwd -c -b /tmp/passwd '$MQTT_USER' '$MQTT_PASS' && cat /tmp/passwd" \
  > "$PASSWD_FILE"

echo "Hotovo: $PASSWD_FILE"
cat "$PASSWD_FILE"
