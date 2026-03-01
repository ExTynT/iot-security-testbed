#!/usr/bin/env bash
set -euo pipefail

echo "=== SMOKE TEST ==="
echo ""
echo "1. MQTT publish test..."
if docker compose exec -T attacker mosquitto_pub -h mosquitto -p 1883 -t telemetry/test -m "hello" 2>/dev/null; then
    echo "MQTT OK"
else
    echo "MQTT FAIL"
fi

echo ""
echo "2. CoAP GET test..."
if docker compose exec -T attacker coap-client -m get coap://coap/ 2>/dev/null; then
    echo "CoAP OK"
else
    echo "CoAP FAIL"
fi

echo ""
echo "3. Checking artifacts..."
RUN_ID=${RUN_ID:-$(grep RUN_ID .env 2>/dev/null | cut -d= -f2 || echo "unknown")}
if [ -d "runs/$RUN_ID/pcap" ] && [ "$(ls -A runs/$RUN_ID/pcap/*.pcap 2>/dev/null | wc -l)" -gt 0 ]; then
    echo "PCAP files found"
else
    echo "No PCAP files yet"
fi

if [ -d "runs/$RUN_ID/logs" ] && [ "$(ls -A runs/$RUN_ID/logs/*.log 2>/dev/null | wc -l)" -gt 0 ]; then
    echo "Log files found"
else
    echo "No log files yet"
fi

echo ""
echo "=== END ==="
