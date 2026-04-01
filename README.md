# IoT Security Testbed

Kontajnerový testbed vytvorený ako praktická časť bakalárskej práce zameranej na analýzu zraniteľností zariadení internetu vecí. Repozitár slúži na reprodukovateľné porovnanie `baseline` a `secure` profilov v troch oblastiach: `MQTT`, `CoAP` a `OTA` aktualizácie.

## Účel projektu

Testbed overuje, ako sa po aktivácii vybraných bezpečnostných opatrení mení výsledok presne definovaných neautorizovaných operácií v kontrolovanom laboratórnom prostredí.

Projekt neslúži ako dôkaz všeobecnej bezpečnosti IoT zariadení. Jeho cieľom je experimentálne demonštrovať účinok konkrétnych mitigácií pri zachovaní rovnakej topológie, rovnakej implementácie a porovnateľného workflowu behov.

## Testované scenáre

| Oblasť | Baseline profil | Secure profil | Očakávaný efekt |
|---|---|---|---|
| MQTT | Broker bez TLS a bez autentifikácie na porte `1883` | TLS na porte `8883`, heslá, ACL | Neautorizovaný publish je odmietnutý a autorizovaný controller ostáva funkčný |
| CoAP | Plaintext CoAP na porte `5683` | DTLS/PSK na porte `5684`, port `5683` blokovaný | Plaintext je blokovaný, zlý PSK zlyhá, správny PSK uspeje |
| OTA | Aktualizácia bez overenia podpisu | Overenie podpisu manifestu pomocou `minisign` | Podpísaná oficiálna aktualizácia uspeje, nedôveryhodná aktualizácia sa odmietne |

## Architektúra v skratke

Testbed je postavený nad stabilnou Compose topológiou. Medzi `baseline` a `secure` profilmi sa nemení identita komponentov ani ich základné väzby. Mení sa iba bezpečnostná konfigurácia služieb.

Hlavné komponenty:

- `dut` - simulované IoT zariadenie
- `mosquitto` - MQTT broker
- `coap` - CoAP server
- `ota` - oficiálny OTA server
- `ota_evil` - alternatívny OTA server pre neautorizovaný aktualizačný scenár
- `attacker` - útokový a kontrolný uzol
- `sniffer_*` - sidecar kontajnery pre pasívny zber prevádzky
- `monitor-collector` - agregácia artefaktov a tvorba `summary.json` a `report.md`

## Požiadavky

| Závislosť | Poznámka |
|---|---|
| Docker Engine + `docker compose` | povinné |
| Git Bash alebo kompatibilný Bash | odporúčané na Windows |
| GNU Make | odporúčané; existujú aj fallback skripty v `scripts/` |
| `minisign` | potrebný pre `ota-secure`; aktuálne skripty na Windows očakávajú binárku v `tools/minisign/minisign-win64/minisign.exe` |

> Na Windows je najčistejší workflow cez Git Bash. `.bat` helpery slúžia iba ako kompatibilitná vrstva, nie ako referenčný workflow pre prácu.
> Adresár `tools/` je lokálna pomocná vrstva a nie je súčasťou verziovaného obsahu repozitára. Ak clone neobsahuje `minisign`, treba ho doplniť lokálne alebo upraviť cestu v skriptoch.

## Rýchly štart

### 1. Zostavenie imageov

```bash
cd iot-security-testbed
make build
```

Fallback bez `make`:

```bash
cd iot-security-testbed
docker compose build
```

### 2. Vygenerovanie MQTT hesiel

```bash
make gen-passwd
```

Fallback bez `make`:

```bash
bash scripts/gen_mqtt_passwd.sh
```

Generované identity:

- `device01` / `device01pass`
- `controller01` / `controller01pass`

### 3. Spustenie scenárov

```bash
make mqtt-baseline
make mqtt-secure

make coap-baseline
make coap-secure

make ota-baseline
make ota-secure
```

Fallback bez `make` pre jeden scenár:

```bash
bash scripts/run_case.sh mqtt-baseline
bash scripts/run_case.sh mqtt-secure

bash scripts/run_case.sh coap-baseline
bash scripts/run_case.sh coap-secure

bash scripts/run_case.sh ota-baseline
bash scripts/run_case.sh ota-secure
```

Každý scenár vykoná rovnaký high-level workflow:

1. vytvorenie nového `run_id`
2. zápis `scenario.txt`
3. `docker compose up -d`
4. `wait_ready.sh`
5. útokové a kontrolné skripty
6. zber artefaktov cez `monitor-collector`
7. `docker compose down --remove-orphans`

### 4. Replikácie

```bash
make replicate-mqtt N=3
make replicate-coap N=3
make replicate-ota N=3
make replicate-all N=3
```

Fallback bez `make`:

```bash
bash scripts/_run_all.sh 3
```

### 5. Agregovaná analýza

```bash
make analyze
```

Fallback bez `make`:

```bash
bash scripts/analyze_runs.sh
```

Výstupy:

- [`runs/analysis.md`](runs/analysis.md)
- [`runs/figures/`](runs/figures/)

## Referenčný dataset pre text práce

Pre finálny text bakalárskej práce je použitá explicitne určená množina šiestich behov:

- `20260322-161426`
- `20260322-161440`
- `20260322-161453`
- `20260322-161510`
- `20260322-161634`
- `20260322-161643`

Autoritatívnu analýzu nad týmto datasetom vytvoríš takto:

```bash
make analyze-final RUN_IDS=20260322-161426,20260322-161440,20260322-161453,20260322-161510,20260322-161634,20260322-161643
```

Fallback bez `make`:

```bash
bash scripts/analyze_runs.sh 20260322-161426,20260322-161440,20260322-161453,20260322-161510,20260322-161634,20260322-161643
```

Výstupy:

- [`runs/analysis-final.md`](runs/analysis-final.md)
- [`runs/figures-final/`](runs/figures-final/)

Vybrané summary súbory referenčných behov:

- [`runs/20260322-161426/results/summary.json`](runs/20260322-161426/results/summary.json)
- [`runs/20260322-161440/results/summary.json`](runs/20260322-161440/results/summary.json)
- [`runs/20260322-161453/results/summary.json`](runs/20260322-161453/results/summary.json)
- [`runs/20260322-161510/results/summary.json`](runs/20260322-161510/results/summary.json)
- [`runs/20260322-161634/results/summary.json`](runs/20260322-161634/results/summary.json)
- [`runs/20260322-161643/results/summary.json`](runs/20260322-161643/results/summary.json)

## Artefakty behov

Každý beh vytvára samostatný priečinok `runs/<run_id>/` s jednotnou štruktúrou:

- `logs/`
- `pcap/`
- `results/summary.json`
- `results/report.md`
- `state/scenario.txt`
- `state/version.txt`

Táto štruktúra je zámerná. Umožňuje spätne prepojiť interpretáciu výsledkov s konkrétnymi logmi, sieťovými stopami a stavovými údajmi.

## Dôležité secure detaily

### MQTT secure

- Mosquitto počúva na porte `8883`.
- Plaintext port `1883` je v secure profile nedostupný.
- `device01` je konto DUT.
- `controller01` je samostatné legitimné kontrolné konto na overenie, že mitigácia nezrušila funkčnú komunikáciu.

### CoAP secure

- Port `5684` používa DTLS/PSK.
- Port `5683` je v secure profile blokovaný cez `iptables`.
- Legitimitu secure profilu dokazujú tri samostatné artefakty:
  - `coap_plain_probe.log`
  - `coap_dtls_wrong_psk.log`
  - `coap_dtls_ok.log`

### OTA secure

- `ota_secure_control_signed.sh` overuje, že podpísaná oficiálna aktualizácia sa dá aplikovať.
- `ota_attack_evil.sh` overuje, že nedôveryhodná aktualizácia sa po aktivácii ochrany neaplikuje.
- Nginx access logy sa ukladajú do:
  - `logs/ota_access.log`
  - `logs/ota_evil_access.log`

## Štruktúra repozitára

```text
iot-security-testbed/
|-- docker-compose.yml
|-- docker-compose.mqtt-secure.yml
|-- docker-compose.coap-secure.yml
|-- docker-compose.ota-secure.yml
|-- Makefile
|-- README.md
|-- configs/
|   |-- mqtt/
|   `-- ota/
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
|   |-- analyze_runs.sh
|   |-- mqtt_*.sh
|   |-- coap_*.sh
|   `-- ota_*.sh
`-- runs/
```

## Troubleshooting

| Problém | Riešenie |
|---|---|
| `mqtt-secure` zlyhá na `passwd` | spusti `make gen-passwd` |
| chceš spustiť len jeden scenár bez `make` | použi `bash scripts/run_case.sh <scenár>` |
| `make` nie je nainštalované | použi fallback príkazy uvedené vyššie |
| `ota-secure` nemá public key | helpery ho doplnia automaticky; `set_minisign_pubkey.sh` je nízkoúrovňový helper |
| CoAP secure visí príliš dlho | používaj aktuálne skripty s `timeout`, nie staré helpery |
| staršie poznámky ukazujú iný workflow | referenčný workflow je tento README + `Makefile` + `wait_ready.sh` |

## Reprodukovateľnosť a limity

Reprodukovateľnosť je podporená:

- fixnou Compose topológiou,
- skriptovaným spúšťaním scenárov,
- samostatným ukladaním logov, PCAP a KPI pre každý beh,
- oddelením `baseline` a `secure` profilov.

Tento projekt je laboratórny testbed. Výsledky sú platné v rámci definovaného Docker prostredia a explicitne zvoleného datasetu. Nejde o produkčný benchmark ani o dôkaz všeobecnej bezpečnosti IoT zariadení.
