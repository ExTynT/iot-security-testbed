#!/usr/bin/env bash
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

MODE="${1:-}"
RUN_IDS="${ANALYZE_RUN_IDS:-}"
OUTPUT_PATH="${ANALYZE_OUTPUT_PATH:-runs/analysis.md}"
FIGURES_SUBDIR="${ANALYZE_FIGURES_SUBDIR:-figures}"
DATASET_MANIFEST="${ANALYZE_DATASET_MANIFEST:-}"
AGGREGATE_JSON_PATH="${ANALYZE_AGGREGATE_JSON_PATH:-runs/analysis-aggregate.json}"
AGGREGATE_MARKDOWN_PATH="${ANALYZE_AGGREGATE_MARKDOWN_PATH:-runs/analysis-aggregate.md}"
LEGACY_AGGREGATE_JSON_PATH="${ANALYZE_LEGACY_AGGREGATE_JSON_PATH:-runs/aggregate.json}"

if [ "$MODE" = "--final-dataset" ]; then
  DATASET_MANIFEST="runs/final-dataset.json"
  OUTPUT_PATH="${ANALYZE_OUTPUT_PATH:-runs/analysis-final.md}"
  FIGURES_SUBDIR="${ANALYZE_FIGURES_SUBDIR:-figures-final}"
  AGGREGATE_JSON_PATH="${ANALYZE_AGGREGATE_JSON_PATH:-runs/analysis-final-aggregate.json}"
  AGGREGATE_MARKDOWN_PATH="${ANALYZE_AGGREGATE_MARKDOWN_PATH:-runs/analysis-final-aggregate.md}"
  LEGACY_AGGREGATE_JSON_PATH="${ANALYZE_LEGACY_AGGREGATE_JSON_PATH:-runs/aggregate-final.json}"
elif [ -n "$MODE" ]; then
  RUN_IDS="$MODE"
fi

RUNS_MOUNT="$PWD/runs"
if command -v cygpath >/dev/null 2>&1; then
  RUNS_MOUNT="$(cygpath -w "$RUNS_MOUNT")"
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"
rm -rf "runs/$FIGURES_SUBDIR"
mkdir -p "runs/$FIGURES_SUBDIR"
docker compose build monitor-collector 1>&2

if [ -n "$DATASET_MANIFEST" ]; then
  docker compose run --rm \
    -e "ANALYZE_DATASET_MANIFEST=$DATASET_MANIFEST" \
    -e "ANALYZE_FIGURES_SUBDIR=$FIGURES_SUBDIR" \
    -e "ANALYZE_AGGREGATE_JSON_PATH=$AGGREGATE_JSON_PATH" \
    -e "ANALYZE_AGGREGATE_MARKDOWN_PATH=$AGGREGATE_MARKDOWN_PATH" \
    -e "ANALYZE_LEGACY_AGGREGATE_JSON_PATH=$LEGACY_AGGREGATE_JSON_PATH" \
    -v "${RUNS_MOUNT}:/runs" --entrypoint python monitor-collector /app/analyze_results.py > "$OUTPUT_PATH"
  echo "Finalna analyza ulozena do $OUTPUT_PATH"
  echo "Manifest finalneho datasetu: $DATASET_MANIFEST"
  echo "Agregovana success-rate tabulka ulozena do $AGGREGATE_MARKDOWN_PATH a $AGGREGATE_JSON_PATH"
  echo "Kompatibilitny alias ulozeny do $LEGACY_AGGREGATE_JSON_PATH"
  echo "Grafy ulozene do runs/$FIGURES_SUBDIR"
elif [ -n "$RUN_IDS" ]; then
  docker compose run --rm \
    -e "ANALYZE_RUN_IDS=$RUN_IDS" \
    -e "ANALYZE_FIGURES_SUBDIR=$FIGURES_SUBDIR" \
    -e "ANALYZE_AGGREGATE_JSON_PATH=$AGGREGATE_JSON_PATH" \
    -e "ANALYZE_AGGREGATE_MARKDOWN_PATH=$AGGREGATE_MARKDOWN_PATH" \
    -e "ANALYZE_LEGACY_AGGREGATE_JSON_PATH=$LEGACY_AGGREGATE_JSON_PATH" \
    -v "${RUNS_MOUNT}:/runs" --entrypoint python monitor-collector /app/analyze_results.py > "$OUTPUT_PATH"
  echo "Finalna analyza ulozena do $OUTPUT_PATH"
  echo "Agregovane success rates ulozene do $AGGREGATE_MARKDOWN_PATH a $AGGREGATE_JSON_PATH"
  echo "Kompatibilitny alias ulozeny do $LEGACY_AGGREGATE_JSON_PATH"
  echo "Vybrate run IDs: $RUN_IDS"
  echo "Grafy ulozene do runs/$FIGURES_SUBDIR"
else
  docker compose run --rm \
    -e "ANALYZE_FIGURES_SUBDIR=$FIGURES_SUBDIR" \
    -e "ANALYZE_AGGREGATE_JSON_PATH=$AGGREGATE_JSON_PATH" \
    -e "ANALYZE_AGGREGATE_MARKDOWN_PATH=$AGGREGATE_MARKDOWN_PATH" \
    -e "ANALYZE_LEGACY_AGGREGATE_JSON_PATH=$LEGACY_AGGREGATE_JSON_PATH" \
    -v "${RUNS_MOUNT}:/runs" --entrypoint python monitor-collector /app/analyze_results.py > "$OUTPUT_PATH"
  echo "Agregovana analyza ulozena do $OUTPUT_PATH"
  echo "Agregovane success rates ulozene do $AGGREGATE_MARKDOWN_PATH a $AGGREGATE_JSON_PATH"
  echo "Kompatibilitny alias ulozeny do $LEGACY_AGGREGATE_JSON_PATH"
  echo "Grafy ulozene do runs/$FIGURES_SUBDIR"
fi
