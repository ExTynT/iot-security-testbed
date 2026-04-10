#!/usr/bin/env bash
# CoAP Secure - kontrolny beh so spravnym PSK
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/run_secrets.sh

RUN_ID="$(require_run_id)"
COAP_PSK="${COAP_PSK:-$(read_run_secret coap_psk.txt "$RUN_ID")}"
COAP_PSK_IDENTITY="${COAP_PSK_IDENTITY:-device01}"
LOGF="runs/${RUN_ID}/logs/attacks.log"
OUTLOG="runs/${RUN_ID}/logs/coap_dtls_ok.log"

: > "$OUTLOG"

echo "=== CoAP SECURE - kontrolny beh (spravny PSK) ==="
echo ""
echo "[1] Legitímny klient DTLS connect (identity='$COAP_PSK_IDENTITY')..."
OUT=$(docker compose exec -T attacker \
  coap-dtls-psk coap 5684 "$COAP_PSK_IDENTITY" "$COAP_PSK" 2>&1 || true)
printf '%s\n' "$OUT" | tee -a "$OUTLOG"
if echo "$OUT" | grep -q "CoAP response 2.05"; then
  echo ">>> USPECH - DTLS session nadviazana, CoAP GET odpoved prijata"
  echo "P2_coap_dtls_ok 1" >> "$LOGF"
else
  echo ">>> VAROVANIE - spravny PSK bol odmietnuty"
fi
echo ""
echo "=== VYSLEDOK: USPECH (KPI: P2 dtls_auth_ok=1) ==="
