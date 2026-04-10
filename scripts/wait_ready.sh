#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

SCENARIO="${1:-}"

case "$SCENARIO" in
  mqtt-baseline|mqtt-secure|coap-baseline|coap-secure|ota-baseline|ota-secure)
    echo "READY: native Compose healthchecks cover service readiness for '$SCENARIO'"
    ;;
  *)
    echo "Pouzitie: $0 <mqtt-baseline|mqtt-secure|coap-baseline|coap-secure|ota-baseline|ota-secure>" >&2
    exit 1
    ;;
esac
