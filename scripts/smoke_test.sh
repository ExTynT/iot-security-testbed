#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

status=0

mark_fail() {
    status=1
}

echo "=== SMOKE TEST ==="
echo ""
echo "1. MQTT publish test..."
if docker compose exec -T attacker mosquitto_pub -h mosquitto -p 1883 -t telemetry/test -m "hello" 2>/dev/null; then
    echo "MQTT OK"
else
    echo "MQTT FAIL"
    mark_fail
fi

echo ""
echo "2. CoAP GET test..."
if docker compose exec -T attacker coap-client -m get coap://coap/ 2>/dev/null; then
    echo "CoAP OK"
else
    echo "CoAP FAIL"
    mark_fail
fi

echo ""
echo "3. Checking artifacts..."
RUN_ID=${RUN_ID:-$(grep RUN_ID .env 2>/dev/null | cut -d= -f2 || echo "unknown")}
pcap_count=0
log_count=0

if [ -d "runs/$RUN_ID/pcap" ]; then
    pcap_count=$(find "runs/$RUN_ID/pcap" -maxdepth 1 -type f -name "*.pcap" | wc -l)
fi

if [ -d "runs/$RUN_ID/logs" ]; then
    log_count=$(find "runs/$RUN_ID/logs" -maxdepth 1 -type f -name "*.log" | wc -l)
fi

if [ "$pcap_count" -gt 0 ]; then
    echo "PCAP files found"
else
    echo "No PCAP files yet"
    mark_fail
fi

if [ "$log_count" -gt 0 ]; then
    echo "Log files found"
else
    echo "No log files yet"
    mark_fail
fi

echo ""
echo "=== END ==="
exit "$status"
