#!/usr/bin/env bash
set -euo pipefail
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RUN_CREATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"

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

python - <<PY
import json
import os
from pathlib import Path

run_root = Path("runs") / ${RUN_ID@Q}
for name in ("pcap", "logs", "results", "state", "secrets"):
    (run_root / name).mkdir(parents=True, exist_ok=True)

# Zdieľané adresáre s artefaktmi sa bind-mountujú do kontajnerov bežiacich pod
# rôznymi neprivilegovanými UID na Linux CI. Sticky world-writable práva
# zachovajú zapisovateľnosť bez toho, aby si kontajnery navzájom prepisovali súbory.
if os.name == "posix":
    for name in ("pcap", "logs", "results", "state"):
        try:
            os.chmod(run_root / name, 0o1777)
        except OSError:
            pass

    try:
        os.chmod(run_root / "secrets", 0o700)
    except OSError:
        pass

run_meta = {
    "run_id": ${RUN_ID@Q},
    "git_commit": ${GIT_COMMIT@Q},
    "created_at": ${RUN_CREATED_AT@Q},
}
(run_root / "state" / "run_meta.json").write_text(
    json.dumps(run_meta, indent=2, ensure_ascii=False) + "\\n",
    encoding="utf-8",
)
PY
printf '%s\n' "$MQTT_DEVICE_PASSWORD" > "runs/$RUN_ID/secrets/mqtt_device_password.txt"
printf '%s\n' "$MQTT_CONTROLLER_PASSWORD" > "runs/$RUN_ID/secrets/mqtt_controller_password.txt"
printf '%s\n' "$COAP_PSK" > "runs/$RUN_ID/secrets/coap_psk.txt"
chmod 600 "runs/$RUN_ID/secrets/"*.txt 2>/dev/null || true
echo "RUN_ID=$RUN_ID pripravene v runs/$RUN_ID/"
