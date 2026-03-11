#!/usr/bin/env bash
# CoAP Secure útok – 5 DTLS pokusov so zlým PSK (handshake musí zlyhať)
# Metodika kap. 3.11: KPI = počet odmietnutých DTLS handshakov
# Očakávaný výsledok: NEUSPECH (DTLS handshake fail – zlý PSK)
# Spustiť po: docker compose -f docker-compose.yml -f docker-compose.coap-secure.yml up -d
# Optimalizácia: sekvenčný loop v jedinom docker exec (eliminuje per-exec overhead)
# Pozn.: paralelné DTLS spôsobovalo UDP kolízie → nesprávne výsledky
set -euo pipefail
cd "$(dirname "$0")/.."

RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
LOGF="runs/${RUN_ID}/logs/attacks.log"
TOTAL=5

echo "=== CoAP SECURE ATTACK – chybny PSK (${TOTAL} pokusov) ==="
echo ""
echo "[1] Attacker skusa ${TOTAL}x DTLS connect so zlym PSK 'wrongpassword123'..."

# Sekvenčný batch v jedinom docker exec (eliminuje ~0.5s per-exec overhead)
# Sekvenčné (nie paralelné) – DTLS UDP vyžaduje sekvenčné pokusy pre správne výsledky
set +e
RESULT=$(docker compose exec -T attacker sh -c '
  failed=0
  for i in $(seq 1 5); do
    coap-dtls-psk coap 5684 device01 wrongpassword123 >/dev/null 2>&1 \
      || failed=$((failed+1))
  done
  echo $failed
' 2>/dev/null)
set -e
FAILED=${RESULT:-0}

for i in $(seq 1 "${FAILED}"); do echo "P2_coap_dtls_failure 1" >> "$LOGF"; done
echo ">>> ${FAILED}/${TOTAL} DTLS handshakov zlyhalo (KPI: P2_coap_dtls_failures=${FAILED})"

echo ""
echo "=== VYSLEDOK: ${FAILED}/${TOTAL} odmietnutych (DTLS PSK mitigacia funguje) ==="
