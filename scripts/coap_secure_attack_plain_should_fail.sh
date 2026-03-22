#!/usr/bin/env bash
# CoAP Secure – plaintext GET na port 5683 (má byť zablokovaný firewallom)
# Metodika kap. 3.11: KPI = počet odmietnutých požiadaviek bez DTLS
# Očakávaný výsledok: NEUSPECH (iptables blokuje port 5683)
# Spustiť po: docker compose -f docker-compose.yml -f docker-compose.coap-secure.yml up -d
# Pozn.: sekvenčné pokusy sú pomalšie, ale deterministickejšie než paralelný burst.
set -euo pipefail
cd "$(dirname "$0")/.."

RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
LOGF="runs/${RUN_ID}/logs/attacks.log"
OUTLOG="runs/${RUN_ID}/logs/coap_plain_probe.log"
TOTAL=3

: > "$OUTLOG"

echo "=== CoAP SECURE ATTACK – plaintext 5683 blokacia (${TOTAL} pokusov) ==="
echo ""
echo "[1] Attacker skusa ${TOTAL}x plaintext GET na port 5683 (firewall ich ma blokovat)..."
echo "    Pouzije sa kratky timeout bez retransmisii, aby scenar nevisel na UDP retry logike."

for _ in $(seq 1 15); do
  if grep -q "CoAP DTLS PSK: 5683=BLOCKED 5684=DTLS+PSK" "runs/${RUN_ID}/logs/coap.log" 2>/dev/null; then
    break
  fi
  sleep 1
done

BLOCKED=0
ACCESSIBLE=0
for i in $(seq 1 "${TOTAL}"); do
  OUT=$(docker compose exec -T attacker \
    sh -lc 'timeout 3 coap-client -m get coap://coap/.well-known/core -B 1 -r 0' 2>&1 || true)
  if echo "$OUT" | grep -qE "2\.05|title="; then
    ACCESSIBLE=$((ACCESSIBLE+1))
    printf 'ACCESSIBLE %02d | %s\n' "$i" "$OUT" >> "$OUTLOG"
  else
    BLOCKED=$((BLOCKED+1))
    printf 'BLOCKED %02d | %s\n' "$i" "${OUT:-timeout_or_drop}" >> "$OUTLOG"
  fi
done

for i in $(seq 1 "${BLOCKED}"); do echo "P2_coap_plain_blocked 1" >> "$LOGF"; done
for i in $(seq 1 "${ACCESSIBLE}"); do echo "P2_coap_plain_accessible 1" >> "$LOGF"; done
echo ">>> ${BLOCKED}/${TOTAL} poziadaviek zablokovanych (KPI: P2_coap_plain_blocked=${BLOCKED})"
if [ "${ACCESSIBLE}" -gt 0 ]; then
  echo ">>> VAROVANIE – ${ACCESSIBLE} pokusov USPESNYCH (iptables nefungoval?)"
fi

echo ""
echo "=== VYSLEDOK: ${BLOCKED}/${TOTAL} zablokovaných (port 5683 blokuje iptables) ==="
