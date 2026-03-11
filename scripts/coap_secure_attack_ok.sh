#!/usr/bin/env bash
# CoAP Secure – legitímny klient so správnym PSK – očakávaný výsledok: USPECH
# Spustiť po: docker compose -f docker-compose.yml -f docker-compose.coap-secure.yml up -d
set -euo pipefail
cd "$(dirname "$0")/.."

# Načítaj PSK z .env
COAP_PSK="${COAP_PSK:-supersecretpsk}"

echo "=== CoAP SECURE – legitímny klient (PSK=$COAP_PSK) ==="
echo ""
echo "[1] Legitímny DTLS connect so správnym PSK..."
docker compose exec -T attacker \
  coap-dtls-psk coap 5684 device01 "$COAP_PSK" \
  && echo ">>> USPECH – DTLS session nadviazaná a CoAP GET odpoveď prijatá"
echo ""
echo "=== VYSLEDOK: USPECH (autorizovaný klient prešiel) ==="
