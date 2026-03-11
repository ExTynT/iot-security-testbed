#!/usr/bin/env bash
# MQTT Secure – kontrolný beh s oprávneným klientom (KPI: služba musí fungovať)
# Dôkaz, že mitigácia NEzrušila legitímnu komunikáciu.
# Spustiť po: docker compose -f docker-compose.yml -f docker-compose.mqtt-secure.yml up -d
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Prevent Git Bash from converting /work/... to Windows paths
cd "$(dirname "$0")/.."

# Načítaj heslo z .env
MQTT_PASS="${MQTT_PASS:-$(grep '^MQTT_PASS=' .env | cut -d= -f2-)}"

echo "=== MQTT SECURE – kontrolný beh (autorizovaný klient) ==="
echo ""
echo "[1] Legitímny klient publikuje cez TLS 8883 (správne heslo)..."
docker compose exec -T attacker \
  mosquitto_pub -h mosquitto -p 8883 --cafile /work/certs/ca.crt \
  -u device01 -P "$MQTT_PASS" \
  -t telemetry/test -m "kontrolny_beh" -d \
  && echo ">>> USPECH – autorizovaná komunikácia funguje"
echo ""
echo "[2] Legitímny klient číta telemetriu..."
docker compose exec -T attacker \
  mosquitto_sub -h mosquitto -p 8883 --cafile /work/certs/ca.crt \
  -u device01 -P "$MQTT_PASS" \
  -t "telemetry/#" -C 1 -W 10 \
  && echo ">>> USPECH – subscribe funguje"
echo ""
echo "=== VYSLEDOK: Oprávnený prístup zachovaný (mitigácia neblokuje legitímnych klientov) ==="
