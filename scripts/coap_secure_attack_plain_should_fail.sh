#!/usr/bin/env bash
# CoAP Secure – plaintext GET na port 5683 (má byť zablokovaný firewallom)
# Metodika kap. 3.11: KPI = počet odmietnutých požiadaviek bez DTLS
# Očakávaný výsledok: NEUSPECH (iptables blokuje port 5683)
# Spustiť po: docker compose -f docker-compose.yml -f docker-compose.coap-secure.yml up -d
# Optimalizácia: 10 pokusov PARALELNE v jedinom docker exec (~1s namiesto ~75s)
set -euo pipefail
cd "$(dirname "$0")/.."

RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
LOGF="runs/${RUN_ID}/logs/attacks.log"
TOTAL=10

echo "=== CoAP SECURE ATTACK – plaintext 5683 blokacia (${TOTAL} pokusov paralelne) ==="
echo ""
echo "[1] Attacker skusa ${TOTAL}x plaintext GET na port 5683 (paralelne, firewall ich ma blokovat)..."

# Parallel batch: všetky pokusy štartujú súčasne v jedinom docker exec
# Každý pokus má 1s timeout (-B 1); keďže bežia paralelne, celkový čas ≈ 1-2s
set +e
RESULT=$(docker compose exec -T attacker sh -c '
  tmpd=$(mktemp -d)
  for i in $(seq 1 10); do
    (OUT=$(coap-client -m get coap://coap/.well-known/core -B 1 2>&1 || true)
     if echo "$OUT" | grep -qE "give up|cannot send|WARN|timeout|No route"; then
       echo 1 > "$tmpd/b_$i"
     else
       echo 1 > "$tmpd/a_$i"
     fi) &
  done
  wait
  b=$(ls "$tmpd"/b_* 2>/dev/null | wc -l)
  a=$(ls "$tmpd"/a_* 2>/dev/null | wc -l)
  rm -rf "$tmpd"
  printf "%d %d\n" "$b" "$a"
' 2>/dev/null)
set -e

BLOCKED=$(echo "$RESULT" | awk '{print $1+0}')
ACCESSIBLE=$(echo "$RESULT" | awk '{print $2+0}')
BLOCKED=${BLOCKED:-0}
ACCESSIBLE=${ACCESSIBLE:-0}

for i in $(seq 1 "${BLOCKED}"); do echo "P2_coap_plain_blocked 1" >> "$LOGF"; done
for i in $(seq 1 "${ACCESSIBLE}"); do echo "P2_coap_plain_accessible 1" >> "$LOGF"; done
echo ">>> ${BLOCKED}/${TOTAL} poziadaviek zablokovanych (KPI: P2_coap_plain_blocked=${BLOCKED})"
if [ "${ACCESSIBLE}" -gt 0 ]; then
  echo ">>> VAROVANIE – ${ACCESSIBLE} pokusov USPESNYCH (iptables nefungoval?)"
fi

echo ""
echo "=== VYSLEDOK: ${BLOCKED}/${TOTAL} zablokovaných (port 5683 blokuje iptables) ==="
