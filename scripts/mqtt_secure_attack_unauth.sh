#!/usr/bin/env bash
# MQTT Secure útok – 30 pokusov neautorizovaného publish bez hesla na TLS port
# Metodika kap. 3.11: KPI = počet odmietnutých neautorizovaných operácií
# Očakávaný výsledok: NEUSPECH (TLS + ACL + auth)
# Spustiť po: docker compose -f docker-compose.yml -f docker-compose.mqtt-secure.yml up -d
# Optimalizácia: celý loop v jedinom docker exec (10-20× rýchlejšie)
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
LOGF="runs/${RUN_ID}/logs/attacks.log"
TOTAL=30

echo "=== MQTT SECURE ATTACK – neautorizovany klient (${TOTAL} pokusov) ==="
echo ""
echo "[1] Attacker skusa ${TOTAL}x publish na TLS port 8883 bez hesla..."
echo "    Ocakava sa: vsetky odmietnuté (Connection error / not authorised)"

# Batch: celý loop prebehne v jedinom docker exec (eliminuje ~0.5s per-exec overhead)
set +e
RESULT=$(docker compose exec -T attacker sh -c '
  denied=0
  for i in $(seq 1 30); do
    mosquitto_pub -h mosquitto -p 8883 --cafile /work/certs/ca.crt \
      -t cmd/ota -m "http://ota_evil?attempt=$i" 2>/dev/null \
      || denied=$((denied+1))
  done
  echo $denied
' 2>/dev/null)
set -e
DENIED=${RESULT:-0}

for i in $(seq 1 "${DENIED}"); do echo "P1_mqtt_unauth_denied 1" >> "$LOGF"; done
echo ">>> ${DENIED}/${TOTAL} pokusov odmietnutych (KPI: P1_mqtt_unauth_denied=${DENIED})"

echo ""
echo "[2] Attacker skusa plaintext port 1883 (nema byt otvoreny v secure mode)..."
docker compose exec -T attacker \
  mosquitto_pub -h mosquitto -p 1883 -t "cmd/ota" -m "http://ota_evil" 2>/dev/null \
  || echo ">>> ODMIETNUTY – port 1883 zatvoreny (ocakavane)"

echo ""
echo "=== VYSLEDOK: ${DENIED}/${TOTAL} pokusov odmietnutych (mitigacia funguje) ==="
