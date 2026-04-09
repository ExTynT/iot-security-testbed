#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
LOGF="runs/${RUN_ID}/logs/attacks.log"
OUTLOG="runs/${RUN_ID}/logs/ota_control.log"
TARGET_VERSION="$(python -c 'import json; print(json.load(open("configs/ota/repo/manifest.json"))["version"])')"
STATE_FILE="runs/${RUN_ID}/state/version.json"
OFFICIAL_LOG="runs/${RUN_ID}/logs/ota_access.log"
read_state_version() {
  python - "$1" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.exists():
    print("unknown")
    raise SystemExit(0)

try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    print("unknown")
    raise SystemExit(0)

print(str(data.get("version", "unknown")))
PY
}

BEFORE_VERSION="$(read_state_version "$STATE_FILE")"
OFFICIAL_HTTP_BEFORE="$(grep -c 'GET /' "$OFFICIAL_LOG" 2>/dev/null || true)"

: > "$OUTLOG"
printf 'BEFORE_VERSION=%s\nOFFICIAL_HTTP_BEFORE=%s\n' "$BEFORE_VERSION" "$OFFICIAL_HTTP_BEFORE" >> "$OUTLOG"

echo "=== OTA SECURE - kontrolny beh (signed official update) ==="
echo ""
echo "[1] Controller spusta OTA z oficialneho servera..."
docker compose exec -T attacker \
  mosquitto_pub -h mosquitto -p 1883 -t cmd/ota -m "http://ota" -d
echo "SIGNED_TRIGGER_SENT" >> "$OUTLOG"
echo ""
echo "[2] Cakam na aplikaciu podpisanej aktualizacie..."
for _ in $(seq 1 20); do
  CURRENT_VERSION="$(read_state_version "$STATE_FILE")"
  if [ "$CURRENT_VERSION" = "$TARGET_VERSION" ] && [ "$CURRENT_VERSION" != "$BEFORE_VERSION" ]; then
    echo "P3_ota_signed_ok 1" >> "$LOGF"
    printf 'SIGNED_OK version=%s\n' "$CURRENT_VERSION" >> "$OUTLOG"
    echo ">>> USPECH - podpisana aktualizacia bola aplikovana (verzia ${CURRENT_VERSION})"
    break
  fi
  sleep 1
done

if ! grep -q '^SIGNED_OK' "$OUTLOG"; then
  CURRENT_VERSION="$(read_state_version "$STATE_FILE")"
  printf 'SIGNED_TIMEOUT version=%s expected=%s\n' "$CURRENT_VERSION" "$TARGET_VERSION" >> "$OUTLOG"
  echo ">>> VAROVANIE - podpisana aktualizacia sa nepotvrdila (aktualna verzia ${CURRENT_VERSION})"
fi

OFFICIAL_HTTP_AFTER="$(grep -c 'GET /' "$OFFICIAL_LOG" 2>/dev/null || true)"
CURRENT_VERSION="$(read_state_version "$STATE_FILE")"
printf 'AFTER_VERSION=%s\nOFFICIAL_HTTP_AFTER=%s\n' "$CURRENT_VERSION" "$OFFICIAL_HTTP_AFTER" >> "$OUTLOG"

echo ""
echo "[3] DUT log (posledne OTA zaznamy):"
grep -i "OTA\|aplikovan" "runs/${RUN_ID}/logs/dut.log" 2>/dev/null | tail -10 \
  || echo "  (log zatial prazdny)"
