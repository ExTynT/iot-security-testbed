#!/usr/bin/env bash
# CoAP Baseline útok – 50 plaintext GET požiadaviek bez DTLS
# Metodika kap. 3.11: KPI = počet úspešných požiadaviek bez autentifikácie
# Očakávaný výsledok: USPECH (plaintext CoAP, port 5683, bez DTLS)
# Spustiť po: docker compose up -d  (bez coap-secure overlayu)
# Optimalizácia: celý loop v jedinom docker exec (10-20× rýchlejšie)
set -euo pipefail
cd "$(dirname "$0")/.."

RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
LOGF="runs/${RUN_ID}/logs/attacks.log"
TOTAL=50

echo "=== CoAP BASELINE ATTACK – plaintext GETs (${TOTAL} pokusov) ==="
echo ""
echo "[1] Discovery – overenie dostupnosti CoAP servera..."
PROBE=$(docker compose exec -T attacker \
  coap-client -m get coap://coap/.well-known/core 2>&1 || true)
echo "$PROBE"
if ! echo "$PROBE" | grep -qE "[[:space:]]</|title=|2\.05"; then
  echo ">>> CoAP server este neodpovedal – cakame 3s..."
  sleep 3
fi

echo ""
echo "[2] Attacker posiela ${TOTAL}x GET coap://coap/.well-known/core (plaintext)..."

# Batch: celý loop prebehne v jedinom docker exec (eliminuje ~0.5s per-exec overhead)
set +e
RESULT=$(docker compose exec -T attacker sh -c '
  count=0
  for i in $(seq 1 50); do
    OUT=$(coap-client -m get coap://coap/.well-known/core 2>&1 || true)
    echo "$OUT" | grep -qE "2\.05|title=" && count=$((count+1)) || true
  done
  echo $count
' 2>/dev/null)
set -e
SUCCESS=${RESULT:-0}

for i in $(seq 1 "${SUCCESS}"); do echo "P2_coap_plain_gets 1" >> "$LOGF"; done
echo ">>> ${SUCCESS}/${TOTAL} GET poziadaviek uspesnych (KPI: P2_coap_plain_gets=${SUCCESS})"

echo ""
echo "[3] Attacker cita /version (GET)..."
docker compose exec -T attacker \
  coap-client -m get coap://coap/version 2>&1 || echo "(resource moze byt nedostupny)"

echo ""
echo "=== VYSLEDOK: ${SUCCESS}/${TOTAL} uspesnych (plaintext CoAP dostupny) ==="
