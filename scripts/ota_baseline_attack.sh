#!/usr/bin/env bash
# Legacy alias kept for backwards compatibility.
# Current canonical script is ota_attack_evil.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

exec bash scripts/ota_attack_evil.sh
