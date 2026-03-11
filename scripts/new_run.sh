#!/usr/bin/env bash
set -euo pipefail
RUN_ID="$(date +%Y%m%d-%H%M%S)"
cat > .env <<EOF
RUN_ID=$RUN_ID

# MQTT (secure profil)
MQTT_USER=device01
MQTT_PASS=device01pass

# CoAP DTLS PSK (secure profil)
COAP_PSK_IDENTITY=device01
COAP_PSK=supersecretpsk
COAP_HINT=CoAP

# minisign public key (secure OTA)
# Generovanie: minisign -G -p configs/ota/minisign.pub -s configs/ota/minisign.key
# Podpis:      minisign -S -s configs/ota/minisign.key -m configs/ota/repo/manifest.json
# Potom vloz obsah riadku 2 z minisign.pub sem:
MINISIGN_PUBKEY=
EOF

mkdir -p "runs/$RUN_ID/pcap" "runs/$RUN_ID/logs" "runs/$RUN_ID/results" "runs/$RUN_ID/state"
echo "RUN_ID=$RUN_ID pripravene v runs/$RUN_ID/"
