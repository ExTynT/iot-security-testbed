#!/usr/bin/env bash
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

RUN_IDS="${ANALYZE_RUN_IDS:-${1:-}}"
OUTPUT_PATH="${ANALYZE_OUTPUT_PATH:-runs/analysis.md}"
FIGURES_SUBDIR="${ANALYZE_FIGURES_SUBDIR:-figures}"

RUNS_MOUNT="$PWD/runs"
if command -v cygpath >/dev/null 2>&1; then
  RUNS_MOUNT="$(cygpath -w "$RUNS_MOUNT")"
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"

if [ -n "$RUN_IDS" ]; then
  docker compose run --rm \
    -e "ANALYZE_RUN_IDS=$RUN_IDS" \
    -e "ANALYZE_FIGURES_SUBDIR=$FIGURES_SUBDIR" \
    -v "${RUNS_MOUNT}:/runs" --entrypoint python monitor-collector /app/analyze_results.py > "$OUTPUT_PATH"
  echo "Finalna analyza ulozena do $OUTPUT_PATH"
  echo "Vybrate run IDs: $RUN_IDS"
  echo "Grafy ulozene do runs/$FIGURES_SUBDIR"
else
  docker compose run --rm \
    -e "ANALYZE_FIGURES_SUBDIR=$FIGURES_SUBDIR" \
    -v "${RUNS_MOUNT}:/runs" --entrypoint python monitor-collector /app/analyze_results.py > "$OUTPUT_PATH"
  echo "Agregovana analyza ulozena do $OUTPUT_PATH"
  echo "Grafy ulozene do runs/$FIGURES_SUBDIR"
fi
