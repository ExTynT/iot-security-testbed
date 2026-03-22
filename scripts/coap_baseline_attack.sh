#!/usr/bin/env bash
# CoAP baseline: plaintext GET without DTLS should succeed.
set -euo pipefail
cd "$(dirname "$0")/.."

RUN_ID="$(grep '^RUN_ID=' .env | cut -d= -f2)"
LOGF="runs/${RUN_ID}/logs/attacks.log"
OUTLOG="runs/${RUN_ID}/logs/coap_baseline_probe.log"
TOTAL=10

: > "$OUTLOG"

echo "=== CoAP BASELINE ATTACK - plaintext GETs (${TOTAL} pokusov) ==="
echo ""
echo "[1] Discovery - overenie dostupnosti CoAP servera..."
PROBE="$(docker compose exec -T attacker coap-client -m get coap://coap/.well-known/core 2>&1 || true)"
printf '%s\n' "$PROBE" | tee -a "$OUTLOG"
if ! printf '%s\n' "$PROBE" | grep -qE "[[:space:]]</|title=|2\.05"; then
  echo ">>> CoAP server este neodpovedal - cakame 3s..."
  sleep 3
fi

echo ""
echo "[2] Attacker posiela ${TOTAL}x GET coap://coap/.well-known/core (plaintext)..."

SUCCESS=0
for i in $(seq 1 "${TOTAL}"); do
  OUT="$(docker compose exec -T attacker coap-client -m get coap://coap/.well-known/core 2>&1 || true)"
  if printf '%s\n' "$OUT" | grep -qE "2\.05|title="; then
    SUCCESS=$((SUCCESS + 1))
    printf 'ACCESSIBLE %02d | %s\n' "$i" "$OUT" >> "$OUTLOG"
  else
    printf 'UNEXPECTED %02d | %s\n' "$i" "${OUT:-no_output}" >> "$OUTLOG"
  fi
done

for _ in $(seq 1 "${SUCCESS}"); do
  echo "P2_coap_plain_gets 1" >> "$LOGF"
done
echo ">>> ${SUCCESS}/${TOTAL} GET poziadaviek uspesnych (KPI: P2_coap_plain_gets=${SUCCESS})"

echo ""
echo "[3] Attacker cita /version (GET)..."
docker compose exec -T attacker \
  coap-client -m get coap://coap/version 2>&1 || echo "(resource moze byt nedostupny)"

echo ""
echo "=== VYSLEDOK: ${SUCCESS}/${TOTAL} uspesnych (plaintext CoAP dostupny) ==="
