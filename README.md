# IoT Security Testbed

Docker-based testbed pre bakalarsku pracu o bezpecnosti IoT komunikacie a OTA aktualizacii.

## Co testbed overuje

Tri oblasti, kazda v dvoch profiloch:

| Protokol | Baseline profil | Secure profil | Hlavny dokaz |
|----------|-----------------|---------------|--------------|
| P1 MQTT | broker bez TLS a bez autentifikacie na porte 1883 | TLS na 8883 + hesla + ACL | neautorizovany publish je odmietnuty a autorizovany controller funguje |
| P2 CoAP | plaintext CoAP na 5683 bez autentifikacie | DTLS/PSK na 5684 + blokovanie 5683 | plaintext je blokovany, zly PSK zlyha, spravny PSK uspeje |
| P3 OTA | OTA bez overenia podpisu | minisign overenie podpisu manifestu | podpisana oficialna aktualizacia uspeje, evil aktualizacia sa odmietne |

Testbed nedokazuje "uplnu bezpecnost IoT". Demonstruje ucinok konkretnych mitigacii na presne definovane neautorizovane operacie v kontrolovanom Docker prostredi.

## Poziadavky

| Zavislost | Poznamka |
|-----------|----------|
| Docker Engine + `docker compose` | povinne |
| Git Bash alebo kompatibilny Bash | odporucane na Windows |
| GNU Make | odporucane, ale existuju aj helper skripty v `scripts/` |

> Na Windows je najcistejsi workflow cez Git Bash. Helper `.bat` skripty su kompatibilitna vrstva, nie hlavny referencny workflow.
> Pri `make`, `run_case.sh` a `_run_all.sh` netreba rucne upravovat `.env`; helpery si ho vytvaraju same.

## Struktura

```text
iot-security-testbed/
|-- docker-compose.yml
|-- docker-compose.mqtt-secure.yml
|-- docker-compose.coap-secure.yml
|-- docker-compose.ota-secure.yml
|-- Makefile
|-- configs/
|   |-- mqtt/
|   |-- ota/
|-- images/
|   |-- attacker/
|   |-- coap-server/
|   |-- dut/
|   |-- monitor-collector/
|   `-- sniffer/
|-- scripts/
|   |-- new_run.sh
|   |-- run_case.sh
|   |-- wait_ready.sh
|   |-- set_minisign_pubkey.sh
|   |-- analyze_runs.sh
|   |-- mqtt_*.sh
|   |-- coap_*.sh
|   `-- ota_*.sh
`-- runs/
```

## Referencny workflow

### 1. Build

```bash
cd iot-security-testbed
make build
```

Ak `make` nie je k dispozicii, overeny fallback v Git Bash je:

```bash
cd iot-security-testbed
docker compose build
```

### 2. MQTT hesla

```bash
make gen-passwd
```

Fallback bez `make`:

```bash
bash scripts/gen_mqtt_passwd.sh
```

Pri `bash scripts/run_case.sh mqtt-secure` a `bash scripts/_run_all.sh ...` sa `passwd` doplni automaticky, ak chyba.

Generuje sa:

- `device01` / `device01pass`
- `controller01` / `controller01pass`

### 3. Jednotlive scenare

```bash
make mqtt-baseline
make mqtt-secure

make coap-baseline
make coap-secure

make ota-baseline
make ota-secure
```

Fallback bez `make` pre jeden scenar:

```bash
bash scripts/run_case.sh mqtt-baseline
bash scripts/run_case.sh mqtt-secure

bash scripts/run_case.sh coap-baseline
bash scripts/run_case.sh coap-secure

bash scripts/run_case.sh ota-baseline
bash scripts/run_case.sh ota-secure
```

Pri `ota-secure` helper automaticky:

- vytvori novy `.env`,
- doplni `MINISIGN_PUBKEY`,
- a ak treba, vygeneruje aj minisign kluce a podpis manifestu.

Kazdy scenar urobi:

1. `new_run.sh`
2. zapis `scenario.txt`
3. `docker compose up -d`
4. `wait_ready.sh`
5. attack/control skripty
6. collector
7. `docker compose down --remove-orphans`

### 4. Replikacie

```bash
make replicate-mqtt N=3
make replicate-coap N=3
make replicate-ota N=3
make replicate-all N=3
```

Ak nie je k dispozicii `make`, existuje fallback:

```bash
bash scripts/_run_all.sh 3
```

### 5. Agregovana analyza

```bash
make analyze
```

Fallback bez `make`:

```bash
bash scripts/analyze_runs.sh
```

Vystup:

- `runs/analysis.md`
- `runs/figures/`

Ak chces autoritativny finalny dataset pre text prace, pouzi explicitny vyber run IDs:

```bash
make analyze-final RUN_IDS=20260322-161426,20260322-161440,20260322-161453,20260322-161510,20260322-161634,20260322-161643
```

Fallback bez `make`:

```bash
bash scripts/analyze_runs.sh 20260322-161426,20260322-161440,20260322-161453,20260322-161510,20260322-161634,20260322-161643
```

Vystup finalneho datasetu:

- `runs/analysis-final.md`
- `runs/figures-final/`

`make analyze` nadalej agreguje vsetko v `runs/`. `make analyze-final` je urceny pre referencnu mnozinu behov, ktoru budes citovat vo vysledkoch a metodike.

## Dolezite secure detaily

### MQTT secure

- Mosquitto pocuva na porte 8883.
- Plaintext port 1883 je v secure profile nedostupny.
- `device01` je konto DUT.
- `controller01` je samostatne legitimne kontrolne konto pre dokaz, ze mitigacia nezrusila funkcnu komunikaciu.

### CoAP secure

- Port 5684 pouziva DTLS/PSK.
- Port 5683 je v secure profile blokovany cez `iptables`.
- Legitimitu secure profilu dokazuju tri oddelene artefakty:
  - `coap_plain_probe.log`
  - `coap_dtls_wrong_psk.log`
  - `coap_dtls_ok.log`

### OTA secure

- `ota_secure_control_signed.sh` overuje, ze podpisana oficialna aktualizacia sa da aplikovat.
- `ota_attack_evil.sh` overuje, ze evil aktualizacia sa po secure ochrane neaplikuje.
- Nginx access logy sa ukladaju do:
  - `logs/ota_access.log`
  - `logs/ota_evil_access.log`

## Artefakty behov

Kazdy run uklada:

- `logs/`
- `pcap/`
- `results/summary.json`
- `results/report.md`
- `state/scenario.txt`
- `state/version.txt`

Priklady overenych secure behov:

- [runs/20260322-153918/results/summary.json](c:/Users/Ivan/Documents/BAKALARKA-REPOZITAR/iot-security-testbed/runs/20260322-153918/results/summary.json)
- [runs/20260322-153949/results/summary.json](c:/Users/Ivan/Documents/BAKALARKA-REPOZITAR/iot-security-testbed/runs/20260322-153949/results/summary.json)
- [runs/20260322-154121/results/summary.json](c:/Users/Ivan/Documents/BAKALARKA-REPOZITAR/iot-security-testbed/runs/20260322-154121/results/summary.json)

## Troubleshooting

| Problem | Riesenie |
|---------|----------|
| `mqtt-secure` zlyha na passwd | spusti `make gen-passwd` |
| chces pustit len jeden scenar bez `make` | pouzi `bash scripts/run_case.sh <scenario>` |
| `make` nie je nainstalovane | pouzi fallback prikazy uvedene vyssie |
| `ota-secure` nema public key | pri `make ota-secure`, `run_case.sh ota-secure` a `_run_all.sh` sa doplni automaticky; manualny `set_minisign_pubkey.sh` je len nizkourovnovy helper |
| CoAP secure visi dlho | pouzivaj aktualne skripty s `timeout`, nie stare helpery |
| Stare skripty/poznamky ukazuju iny workflow | referencny workflow je README + Makefile + `wait_ready.sh` |

## Reprodukovatelnost

Reprodukovatelnost je podporena:

- fixnou compose topologiou,
- skriptovanym spustanim scenarov,
- per-run ulozenim logov, PCAP a KPI,
- oddelenim baseline a secure profilov.

Nie je to garantovana reprodukcia "na lubovolnom stroji bez rozdielu". Je to reprodukovatelny laboratorny testbed v ramci definovanych zavislosti a lokalneho Docker prostredia.
