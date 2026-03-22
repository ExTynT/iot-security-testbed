#!/usr/bin/env bash
# Vygeneruje configs/mqtt/secure/passwd pomocou Mosquitto passwd utility v Dockeri.
# Spusti RAZ pred prvým použitím docker-compose.mqtt-secure.yml.
set -euo pipefail
cd "$(dirname "$0")/.."

PASSWD_FILE="configs/mqtt/secure/passwd"
MQTT_USER="${MQTT_USER:-device01}"
MQTT_PASS="${MQTT_PASS:-device01pass}"
MQTT_CTRL_USER="${MQTT_CTRL_USER:-controller01}"
MQTT_CTRL_PASS="${MQTT_CTRL_PASS:-controller01pass}"

echo "Generujem $PASSWD_FILE pre user=$MQTT_USER a user=$MQTT_CTRL_USER ..."

docker run --rm eclipse-mosquitto:2.0.18 \
  sh -c "mosquitto_passwd -c -b /tmp/passwd '$MQTT_USER' '$MQTT_PASS' && \
         mosquitto_passwd -b /tmp/passwd '$MQTT_CTRL_USER' '$MQTT_CTRL_PASS' && \
         cat /tmp/passwd" \
  > "$PASSWD_FILE"

chmod 600 "$PASSWD_FILE" 2>/dev/null || true

echo "Hotovo: $PASSWD_FILE"
cat "$PASSWD_FILE"
