#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

PUBKEY="$(sed -n '2p' configs/ota/minisign.pub | tr -d '\r\n')"
if [ -z "$PUBKEY" ]; then
  echo "Chyba: nepodarilo sa nacitat minisign public key z configs/ota/minisign.pub" >&2
  exit 1
fi

python - "$PUBKEY" <<'PY'
from pathlib import Path
import sys

pubkey = sys.argv[1]
env_path = Path(".env")
lines = env_path.read_text(encoding="utf-8").splitlines()
updated = []
replaced = False
for line in lines:
    if line.startswith("MINISIGN_PUBKEY="):
        updated.append(f"MINISIGN_PUBKEY={pubkey}")
        replaced = True
    else:
        updated.append(line)

if not replaced:
    updated.append(f"MINISIGN_PUBKEY={pubkey}")

env_path.write_text("\n".join(updated) + "\n", encoding="utf-8")
PY

echo "MINISIGN_PUBKEY nastaveny v .env"
