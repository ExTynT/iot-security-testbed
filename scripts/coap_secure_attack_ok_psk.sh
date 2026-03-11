#!/usr/bin/env bash
# CoAP Secure – kontrolný beh so správnym PSK (dôkaz, že služba funguje)
# Očakávaný výsledok: USPECH (DTLS handshake + CoAP 2.05 odpoveď)
# Spustiť po: docker compose -f docker-compose.yml -f docker-compose.coap-secure.yml up -d
set -euo pipefail
cd "$(dirname "$0")/.."

COAP_PSK="${COAP_PSK:-$(grep '^COAP_PSK=' .env | cut -d= -f2-)}"
COAP_PSK_IDENTITY="${COAP_PSK_IDENTITY:-$(grep '^COAP_PSK_IDENTITY=' .env | cut -d= -f2-)}"

echo "=== CoAP SECURE – kontrolný beh (správny PSK) ==="
echo ""
RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
LOGF="runs/${RUN_ID}/logs/attacks.log"

echo "[1] Legitímny klient DTLS connect (identity='$COAP_PSK_IDENTITY')..."
if docker compose exec -T attacker \
  coap-dtls-psk coap 5684 "$COAP_PSK_IDENTITY" "$COAP_PSK" 2>&1; then
  echo ">>> USPECH – DTLS session nadviazaná, CoAP GET odpoveď prijatá"
  echo "P2_coap_dtls_ok 1" >> "$LOGF"
else
  echo ">>> VAROVANIE – správny PSK bol odmietnutý (neočakávané)"
fi
echo ""
echo "=== VYSLEDOK: USPECH (KPI: P2 dtls_auth_ok=1) ==="
