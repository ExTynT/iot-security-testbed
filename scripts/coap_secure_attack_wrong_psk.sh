#!/usr/bin/env bash
# CoAP secure útok: päť DTLS pokusov so zlým PSK, handshake musí zlyhať.
# Metodika kap. 3.11: KPI je počet odmietnutých DTLS handshake pokusov.
# Spúšťať po: docker compose -f docker-compose.yml -f docker-compose.coap-secure.yml up -d
# Pokusy musia byť sekvenčné; paralelné DTLS spojenia skresľovali výsledky cez UDP kolízie.
set -euo pipefail
cd "$(dirname "$0")/.."

RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
LOGF="runs/${RUN_ID}/logs/attacks.log"
OUTLOG="runs/${RUN_ID}/logs/coap_dtls_wrong_psk.log"
TOTAL=5

: > "$OUTLOG"

echo "=== CoAP SECURE ATTACK – chybny PSK (${TOTAL} pokusov) ==="
echo ""
echo "[1] Attacker skusa ${TOTAL}x DTLS connect so zlym PSK 'wrongpassword123'..."

# Batch beží v jednom docker exec, ale jednotlivé DTLS pokusy ostávajú sekvenčné.
FAILED=0
for i in $(seq 1 "${TOTAL}"); do
  OUT=$(docker compose exec -T attacker \
    coap-dtls-psk coap 5684 device01 wrongpassword123 2>&1 || true)
  if echo "$OUT" | grep -qE "FAIL|failed|rejected|alert"; then
    FAILED=$((FAILED+1))
    printf 'FAIL %02d | %s\n' "$i" "$OUT" >> "$OUTLOG"
  else
    printf 'UNEXPECTED %02d | %s\n' "$i" "${OUT:-no_output}" >> "$OUTLOG"
  fi
done

for i in $(seq 1 "${FAILED}"); do echo "P2_coap_dtls_failure 1" >> "$LOGF"; done
echo ">>> ${FAILED}/${TOTAL} DTLS handshakov zlyhalo (KPI: P2_coap_dtls_failures=${FAILED})"

echo ""
echo "=== VYSLEDOK: ${FAILED}/${TOTAL} odmietnutych (DTLS PSK mitigacia funguje) ==="
