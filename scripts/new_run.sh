#!/usr/bin/env bash
set -euo pipefail
RUN_ID="$(date +%Y%m%d-%H%M%S)"

generate_secret() {
  python - <<'PY'
import secrets

print(secrets.token_hex(16))
PY
}

MQTT_DEVICE_PASSWORD="$(generate_secret)"
MQTT_CONTROLLER_PASSWORD="$(generate_secret)"
COAP_PSK="$(generate_secret)"

cat > .env <<EOF
RUN_ID=$RUN_ID
EOF

mkdir -p "runs/$RUN_ID/pcap" "runs/$RUN_ID/logs" "runs/$RUN_ID/results" "runs/$RUN_ID/state" "runs/$RUN_ID/secrets"
printf '%s\n' "$MQTT_DEVICE_PASSWORD" > "runs/$RUN_ID/secrets/mqtt_device_password.txt"
printf '%s\n' "$MQTT_CONTROLLER_PASSWORD" > "runs/$RUN_ID/secrets/mqtt_controller_password.txt"
printf '%s\n' "$COAP_PSK" > "runs/$RUN_ID/secrets/coap_psk.txt"
chmod 600 "runs/$RUN_ID/secrets/"*.txt 2>/dev/null || true
echo "RUN_ID=$RUN_ID pripravene v runs/$RUN_ID/"
