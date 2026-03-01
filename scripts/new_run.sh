#!/usr/bin/env bash
set -euo pipefail
RUN_ID="$(date +%Y%m%d-%H%M)"
cat > .env <<EOF
RUN_ID=$RUN_ID
# CoAP DTLS PSK (secure profil)
COAP_PSK_IDENTITY=device01
COAP_PSK=supersecretpsk
COAP_HINT=CoAP
# minisign public key (secure OTA) – doplníš neskôr
MINISIGN_PUBKEY=
EOF

mkdir -p "runs/$RUN_ID/pcap" "runs/$RUN_ID/logs" "runs/$RUN_ID/results"
echo "RUN_ID=$RUN_ID pripravené v runs/$RUN_ID/"
