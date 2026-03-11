#!/usr/bin/env bash
# Spustí všetkých 6 scenárov 3x za sebou (splnenie metodiky: min. 3 replikácie)
# Metodika kap. 3.12: Baseline behy A B C + Re-test A B C (min. 3 replikácie)
# Náhrada za make replicate-all keď make nie je k dispozícii
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Prevent Git Bash path conversion for /work/... container paths
cd "$(dirname "$0")/.."

BASE="-f docker-compose.yml"
MQTT_S="-f docker-compose.yml -f docker-compose.mqtt-secure.yml"
COAP_S="-f docker-compose.yml -f docker-compose.coap-secure.yml"
OTA_S="-f docker-compose.yml -f docker-compose.ota-secure.yml"

REPLICATIONS=${1:-3}   # Počet replikácií (predvolene 3, dá sa zmeniť: bash _run_all.sh 5)

run_collector() {
  docker compose run --rm monitor-collector
}

echo ""
echo "========================================"
echo "  IoT Security Testbed – Replikácie"
echo "  Počet replikácií: ${REPLICATIONS}"
echo "========================================"

# ══════════════════════════════════════════════════════════════
# P1 – MQTT BASELINE (${REPLICATIONS} replikácií)
# ══════════════════════════════════════════════════════════════
for rep in $(seq 1 ${REPLICATIONS}); do
echo ""
echo "████████████████████████████████████████"
echo "  P1 – MQTT BASELINE  [rep ${rep}/${REPLICATIONS}]"
echo "████████████████████████████████████████"
bash scripts/new_run.sh
RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
echo "mqtt-baseline" > runs/${RUN_ID}/state/scenario.txt
docker compose $BASE up -d
sleep 6
bash scripts/mqtt_baseline_attack.sh
run_collector
docker compose $BASE down --remove-orphans
done

# ══════════════════════════════════════════════════════════════
# P1 – MQTT SECURE (${REPLICATIONS} replikácií)
# ══════════════════════════════════════════════════════════════
for rep in $(seq 1 ${REPLICATIONS}); do
echo ""
echo "████████████████████████████████████████"
echo "  P1 – MQTT SECURE  [rep ${rep}/${REPLICATIONS}]"
echo "████████████████████████████████████████"
bash scripts/new_run.sh
RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
echo "mqtt-secure" > runs/${RUN_ID}/state/scenario.txt
docker compose $MQTT_S up -d
sleep 6
bash scripts/mqtt_secure_attack_unauth.sh
bash scripts/mqtt_secure_control_auth.sh
run_collector
docker compose $MQTT_S down --remove-orphans
done

# ══════════════════════════════════════════════════════════════
# P2 – CoAP BASELINE (${REPLICATIONS} replikácií)
# ══════════════════════════════════════════════════════════════
for rep in $(seq 1 ${REPLICATIONS}); do
echo ""
echo "████████████████████████████████████████"
echo "  P2 – CoAP BASELINE  [rep ${rep}/${REPLICATIONS}]"
echo "████████████████████████████████████████"
bash scripts/new_run.sh
RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
echo "coap-baseline" > runs/${RUN_ID}/state/scenario.txt
docker compose $BASE up -d
sleep 6
bash scripts/coap_baseline_attack.sh
run_collector
docker compose $BASE down --remove-orphans
done

# ══════════════════════════════════════════════════════════════
# P2 – CoAP SECURE (${REPLICATIONS} replikácií)
# ══════════════════════════════════════════════════════════════
for rep in $(seq 1 ${REPLICATIONS}); do
echo ""
echo "████████████████████████████████████████"
echo "  P2 – CoAP SECURE  [rep ${rep}/${REPLICATIONS}]"
echo "████████████████████████████████████████"
bash scripts/new_run.sh
RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
echo "coap-secure" > runs/${RUN_ID}/state/scenario.txt
docker compose $COAP_S up -d
sleep 6
bash scripts/coap_secure_attack_plain_should_fail.sh
bash scripts/coap_secure_attack_wrong_psk.sh
bash scripts/coap_secure_attack_ok_psk.sh
run_collector
docker compose $COAP_S down --remove-orphans
done

# ══════════════════════════════════════════════════════════════
# P3 – OTA BASELINE (${REPLICATIONS} replikácií)
# ══════════════════════════════════════════════════════════════
for rep in $(seq 1 ${REPLICATIONS}); do
echo ""
echo "████████████████████████████████████████"
echo "  P3 – OTA BASELINE  [rep ${rep}/${REPLICATIONS}]"
echo "████████████████████████████████████████"
bash scripts/new_run.sh
RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
echo "ota-baseline" > runs/${RUN_ID}/state/scenario.txt
docker compose $BASE up -d
sleep 6
bash scripts/ota_attack_evil.sh
run_collector
docker compose $BASE down --remove-orphans
done

# ══════════════════════════════════════════════════════════════
# P3 – OTA SECURE (${REPLICATIONS} replikácií)
# ══════════════════════════════════════════════════════════════
for rep in $(seq 1 ${REPLICATIONS}); do
echo ""
echo "████████████████████████████████████████"
echo "  P3 – OTA SECURE  [rep ${rep}/${REPLICATIONS}]"
echo "████████████████████████████████████████"
bash scripts/new_run.sh
RUN_ID=$(grep '^RUN_ID=' .env | cut -d= -f2)
echo "ota-secure" > runs/${RUN_ID}/state/scenario.txt
# new_run.sh resetuje MINISIGN_PUBKEY – treba znova nastaviť
PUBKEY=$(sed -n '2p' configs/ota/minisign.pub)
sed -i "s|^MINISIGN_PUBKEY=.*|MINISIGN_PUBKEY=$PUBKEY|" .env
docker compose $OTA_S up -d
sleep 5
docker compose $OTA_S up -d --force-recreate dut
sleep 4
bash scripts/ota_attack_evil.sh
run_collector
docker compose $OTA_S down --remove-orphans
done

# ══════════════════════════════════════════════════════════════
echo ""
echo "████████████████████████████████████████"
echo "  VSETKY SCENARE DOKONCENE"
echo "  ${REPLICATIONS} replikacii x 6 scenárov = $((REPLICATIONS * 6)) behov celkom"
echo "████████████████████████████████████████"
echo ""
ls -la runs/*/results/summary.json 2>/dev/null || true
