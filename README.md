# IoT Security Testbed

Kontajnerový testbed vytvorený ako praktická časť bakalárskej práce zameranej na analýzu zraniteľností zariadení internetu vecí. Repozitár slúži na reprodukovateľné porovnanie profilov `baseline` a `secure` v troch oblastiach: `MQTT`, `CoAP` a `OTA` aktualizácie.

## Účel projektu

Testbed overuje, ako sa po aktivácii vybraných bezpečnostných opatrení mení výsledok presne definovaných neautorizovaných operácií v kontrolovanom laboratórnom prostredí.

Projekt neslúži ako dôkaz všeobecnej bezpečnosti IoT zariadení. Jeho cieľom je experimentálne demonštrovať účinok konkrétnych mitigácií pri zachovaní rovnakej topológie, rovnakej implementácie a porovnateľného workflowu behov.

## Kľúčové vlastnosti

- pevná Docker Compose topológia pre porovnanie `baseline` a `secure` profilov
- samostatné scenáre pre `MQTT`, `CoAP` a `OTA` s konzistentným artefaktovým modelom
- per-run proveniencia cez `run_id`, `git_commit`, `created_at` a `compose_files`
- schémovo fixovaný export `summary.json` validovaný proti `schemas/summary.schema.json`
- agregovaná analýza s textovým reportom, grafmi a strojovo čitateľným JSON výstupom

## Testované scenáre

| Oblasť | Baseline profil | Secure profil | Očakávaný efekt |
|---|---|---|---|
| MQTT | Broker bez TLS a bez autentifikácie na porte `1883` | TLS na porte `8883`, heslá, ACL | Neautorizovaný publish je odmietnutý a autorizovaný controller ostáva funkčný |
| CoAP | Plaintext CoAP na porte `5683` | DTLS/PSK na porte `5684`, plaintext endpoint `5683` nie je vytvorený | Plaintext je nedostupný, zlý PSK zlyhá, správny PSK uspeje |
| OTA | Aktualizácia bez overenia podpisu | Overenie podpisu manifestu pomocou `minisign` | Podpísaná oficiálna aktualizácia uspeje, nedôveryhodná aktualizácia sa odmietne |

## Architektúra v skratke

Testbed je postavený nad stabilnou Compose topológiou. Medzi profilmi `baseline` a `secure` sa nemení identita komponentov ani ich základné väzby. Mení sa iba bezpečnostná konfigurácia služieb a pridružených klientov.

Hlavné komponenty:

- `dut` - simulované IoT zariadenie
- `mosquitto` - MQTT broker
- `coap` - CoAP server
- `ota` - oficiálny OTA server
- `ota_evil` - alternatívny OTA server pre neautorizovaný aktualizačný scenár
- `attacker` - útokový a kontrolný uzol
- `sniffer_*` - sidecar kontajnery pre pasívny zber prevádzky
- `monitor-collector` - agregácia artefaktov a tvorba `summary.json`, `report.md` a `fig_kpi.png`

## Požiadavky na spustenie

| Závislosť | Poznámka |
|---|---|
| Docker Engine + `docker compose` | povinné |
| Git Bash alebo kompatibilný Bash | odporúčané na Windows |
| GNU Make | odporúčané; existujú aj fallback skripty v `scripts/` |
| `minisign` | potrebný pre `ota-secure`; predvolene sa očakáva `minisign` dostupný v `PATH` |

> Na Windows je najčistejší postup cez Git Bash. `.bat` helpery slúžia iba ako kompatibilitná vrstva, nie ako referenčný spôsob práce.
> Linux/macOS: default `minisign`. Windows Git Bash: nastav `MINISIGN_BIN=/c/.../minisign.exe`.

## Požiadavky na lokálny vývoj a testy

Pre lokálne `lint`, `test` a časť smoke validácie je potrebný aj Python toolchain:

- Python `3.12`
- `pip`
- balíky `pytest`, `ruff`, `jsonschema`, `pyyaml`

Odporúčaný lokálny príkaz:

```bash
python -m pip install --upgrade pip pytest ruff jsonschema pyyaml
```

Referenčný CI workflow ich inštaluje priamo v `.github/workflows/ci.yml`.

## Rýchly štart

### 1. Zostavenie imageov

```bash
cd iot-security-testbed
make build
```

Alternatíva bez `make`:

```bash
cd iot-security-testbed
docker compose build
```

### 2. Inicializácia nového runu a per-run secrets

```bash
bash scripts/new_run.sh
```

Skript vytvorí `.env` iba s `RUN_ID` a zároveň vygeneruje per-run secret súbory:

- `runs/<run_id>/secrets/mqtt_device_password.txt`
- `runs/<run_id>/secrets/mqtt_controller_password.txt`
- `runs/<run_id>/secrets/coap_psk.txt`
- `runs/<run_id>/state/run_meta.json`

`run_meta.json` obsahuje minimálnu provenienciu behu:

- `run_id`
- `git_commit`
- `created_at`

Nesenzitívne identity ostávajú pevné:

- `device01`
- `controller01`

### 3. Spustenie scenárov

```bash
make mqtt-baseline
make mqtt-secure

make coap-baseline
make coap-secure

make ota-baseline
make ota-secure
```

Alternatíva bez `make` pre jeden scenár:

```bash
bash scripts/run_case.sh mqtt-baseline
bash scripts/run_case.sh mqtt-secure

bash scripts/run_case.sh coap-baseline
bash scripts/run_case.sh coap-secure

bash scripts/run_case.sh ota-baseline
bash scripts/run_case.sh ota-secure
```

Všetky scenáre používajú rovnaký základný priebeh:

1. vytvorenie nového `run_id`
2. vygenerovanie per-run secret súborov
3. zápis `scenario.txt` a `compose_files.txt`
4. `docker compose up -d --wait`
5. `wait_ready.sh`
6. útokové a kontrolné skripty
7. zber artefaktov cez `monitor-collector`
8. `docker compose down --remove-orphans`

Výnimkou je `ota-secure`, ktorý pred behom ešte zabezpečí prítomnosť `minisign` kľúčov a uloží podpis manifestu do per-run `state/manifest.json.minisig`.

`summary.json` je schémovo pevný a samopopisný artefakt. Validuje sa proti [`schemas/summary.schema.json`](schemas/summary.schema.json) a okrem KPI obsahuje aj:

- `meta.schema_version`
- `meta.run_id`
- `meta.profile`
- `meta.git_commit`
- `meta.created_at`
- `meta.compose_files`

### 4. Replikácie

```bash
make replicate-mqtt N=3
make replicate-coap N=3
make replicate-ota N=3
make replicate-all N=3
```

Alternatíva bez `make`:

```bash
bash scripts/_run_all.sh 3
```

### 5. Agregovaná analýza

```bash
make analyze
```

Alternatíva bez `make`:

```bash
bash scripts/analyze_runs.sh
```

Výstupy v tomto režime sú lokálne exploratory artefakty, ktoré sa zámerne
necommitujú do repozitára:

- `runs/analysis.md`
- `runs/analysis-aggregate.md`
- `runs/analysis-aggregate.json`
- `runs/aggregate.json`
- `runs/figures/`

Tento režim je vhodný na priebežnú prácu s ľubovoľnými lokálnymi behovmi.
Nie je autoritatívnym zdrojom pre finálny text práce.

## Artefakty behov

Každý beh vytvára samostatný priečinok `runs/<run_id>/` s jednotnou štruktúrou:

- `secrets/`
- `logs/`
- `pcap/`
- `results/summary.json`
- `results/report.md`
- `results/fig_kpi.png`
- `state/scenario.txt`
- `state/compose_files.txt`
- `state/run_meta.json`
- `state/manifest.json.minisig` pri `ota-secure`
- `state/version.json` alebo `state/version.txt`, ak DUT exportuje stav verzie

Táto štruktúra je zámerná. Umožňuje spätne prepojiť interpretáciu výsledkov s konkrétnymi logmi, sieťovými stopami, provenienciou runu a identitou použitej Compose konfigurácie. Na presnú rekonštrukciu scenára je potrebné prepnutie repozitára na zaznamenaný `git_commit`; pri secure behoch treba navyše zohľadniť per-run secrets a v prípade `ota-secure` aj lokálne dostupný `minisign`.

## Dôležité secure detaily

### MQTT secure

- Mosquitto počúva na porte `8883`.
- Plaintext port `1883` je v secure profile nedostupný.
- `device01` je konto DUT.
- `controller01` je samostatné legitimné kontrolné konto na overenie, že mitigácia nezrušila funkčnú komunikáciu.

### CoAP secure

- Port `5684` používa DTLS/PSK.
- Secure build vytvára iba DTLS endpoint na porte `5684`.
- Plaintext endpoint na porte `5683` sa v secure profile nevytvára a ostáva zatvorený.
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

## Referenčný dataset pre text práce

Pre finálny text bakalárskej práce je použitá explicitne určená množina šiestich behov
z plného rerunu na aktuálnom `main` stave repozitára zo dňa `2026-04-11`
na committe `c7556d124d5818cb7199af6ab1ab004efacd3317`:

- `20260411-235046`
- `20260411-235112`
- `20260411-235159`
- `20260411-235226`
- `20260411-235401`
- `20260411-235510`

Repo ich fixuje aj v machine-readable manifeste
[`runs/final-dataset.json`](runs/final-dataset.json), aby bol výber datasetu auditovateľný aj
bez dohľadávania v texte README.

`runs/final-dataset.json` je jediný zdroj pravdy pre:

- výber šiestich finálnych behov,
- cesty k commitnutým referenčným `summary.json`,
- generovanie finálneho reportu,
- generovanie finálnych grafov a agregovaných JSON/Markdown výstupov.

Autoritatívnu analýzu nad týmto datasetom vytvoríš takto:

```bash
make analyze-final
```

Fallback bez `make`:

```bash
bash scripts/analyze_runs.sh --final-dataset
```

Výstupy:

- [`runs/final-dataset.json`](runs/final-dataset.json)
- [`runs/analysis-final.md`](runs/analysis-final.md)
- [`runs/analysis-final-aggregate.md`](runs/analysis-final-aggregate.md)
- [`runs/analysis-final-aggregate.json`](runs/analysis-final-aggregate.json)
- [`runs/aggregate-final.json`](runs/aggregate-final.json)
- [`runs/figures-final/`](runs/figures-final/)

Vybrané summary súbory referenčných behov sú commitnuté v lightweight tvare:

- [`runs/reference/20260411-235046/summary.json`](runs/reference/20260411-235046/summary.json)
- [`runs/reference/20260411-235112/summary.json`](runs/reference/20260411-235112/summary.json)
- [`runs/reference/20260411-235159/summary.json`](runs/reference/20260411-235159/summary.json)
- [`runs/reference/20260411-235226/summary.json`](runs/reference/20260411-235226/summary.json)
- [`runs/reference/20260411-235401/summary.json`](runs/reference/20260411-235401/summary.json)
- [`runs/reference/20260411-235510/summary.json`](runs/reference/20260411-235510/summary.json)

## Štruktúra repozitára

Skrátená technická mapa hlavných vstupných bodov:

```text
iot-security-testbed/
|-- .github/
|   `-- workflows/
|       |-- ci.yml
|       `-- codeql.yml
|-- configs/
|   |-- mqtt/
|   `-- ota/
|-- images/
|   |-- attacker/
|   |-- coap-server/
|   |-- dut/
|   |-- monitor-collector/
|   `-- sniffer/
|-- schemas/
|   `-- summary.schema.json
|-- scripts/
|   |-- new_run.sh
|   |-- run_case.sh
|   |-- wait_ready.sh
|   |-- smoke_test.sh
|   |-- analyze_runs.sh
|   |-- mqtt_*.sh
|   |-- coap_*.sh
|   `-- ota_*.sh
|-- tests/
|   |-- fixtures/
|   |-- test_collector.py
|   |-- test_compose_hardening.py
|   |-- test_analyze_results_aggregate.py
|   |-- test_dut_ota.py
|   |-- test_run_secrets.py
|   `-- test_workflows.py
|-- runs/
|   |-- reference/
|   |-- final-dataset.json
|   |-- analysis-final.md
|   |-- analysis-final-aggregate.json
|   |-- analysis-final-aggregate.md
|   |-- aggregate-final.json
|   `-- figures-final/
|-- docker-compose.yml
|-- docker-compose.mqtt-secure.yml
|-- docker-compose.coap-secure.yml
|-- docker-compose.ota-secure.yml
|-- docker-compose.secure.yml
|-- Makefile
|-- LICENSE
|-- pyproject.toml
|-- README.md
|-- SECURITY.md
`-- CITATION.cff
```

`docker-compose.secure.yml` je zámerne ponechaný len ako deprecated compatibility placeholder. Autoritatívne secure scenáre sú rozdelené do súborov `docker-compose.mqtt-secure.yml`, `docker-compose.coap-secure.yml` a `docker-compose.ota-secure.yml`.

## Testovanie a CI

Lokálna aj CI verifikácia je zámerne rozdelená do troch vrstiev:

1. `make lint`
   overuje statickú kvalitu Python častí (`collector`, agregovaná analýza, testy) pomocou `ruff`.
2. `make test`
   spúšťa `pytest` nad fixture kontraktmi collectora, validáciou schémy `summary.json`, compose hardening testami, agregovanou analýzou, OTA validáciou, per-run secrets a workflow pinningom.
3. `make smoke-ci`
   vykoná end-to-end baseline smoke run:
   - vytvorí nový `run_id`,
   - zdvihne Compose stack,
   - vykoná live smoke check nad MQTT a CoAP,
   - spustí `monitor-collector`,
   - zopakuje smoke check nad `state/run_meta.json` a `results/summary.json`,
   - overí, že `summary.json.meta.run_id == RUN_ID`.

GitHub Actions workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) spúšťa rovnaké tri vrstvy. Pri smoke rune uploaduje:

- `.env`
- `logs/**`
- `pcap/**`
- `results/**`
- `state/**`

CI teda nezlyhá len pri padnutej službe, ale aj vtedy, keď sa collector nespustí, keď chýba proveniencia v `state/` alebo keď nevznikne `summary.json` s očakávaným `meta.run_id`.

Popri hlavnom CI je v repozitári aj workflow [`.github/workflows/codeql.yml`](.github/workflows/codeql.yml), ktorý cez GitHub CodeQL vykonáva statickú bezpečnostnú analýzu pre `python` a GitHub Actions workflowy.

## Bezpečnosť a nahlasovanie zraniteľností

Pravidlá pre zodpovedné nahlasovanie sú uvedené v [SECURITY.md](SECURITY.md). Repozitár je verejný a tematicky bezpečnostný, preto sa odporúča nepoužívať verejné issue na zverejnenie exploit detailov pred triage.

## Citácia a väzba na prácu

Ak repozitár používaš ako technický zdroj pre bakalársku prácu, článok alebo interný report, pri citácii uveď aspoň:

- názov repozitára
- autora alebo organizáciu
- URL repozitára
- dátum prístupu
- presný `git_commit`

Ak cituješ konkrétny experimentálny výsledok, doplň aj príslušný `run_id`, aby bolo možné spätne dohľadať artefakty a agregovanú interpretáciu.

Pre GitHub, citačné manažéry a strojové spracovanie je pripravený aj súbor
[`CITATION.cff`](CITATION.cff).

## Troubleshooting

| Problém | Riešenie |
|---|---|
| `mqtt-secure` zlyhá na `passwd` | spusti `bash scripts/new_run.sh`, over existenciu `runs/<run_id>/secrets/*.txt` a scenár spusť znova |
| `minisign not found` pri `ota-secure` | nainštaluj `minisign` alebo nastav `MINISIGN_BIN` na explicitnú cestu k binárke |
| chceš spustiť len jeden scenár bez `make` | použi `bash scripts/run_case.sh <scenár>` |
| `make` nie je nainštalované | použi fallback príkazy uvedené vyššie |
| lokálne `make test` zlyhá na chýbajúcom Pythone | doinštaluj Python `3.12` a balíky `pytest`, `ruff`, `jsonschema`, `pyyaml` |
| CoAP secure visí príliš dlho | používaj aktuálne skripty s `timeout`, nie staré helpery |
| staršie poznámky ukazujú iný workflow | referenčný postup je tento README spolu s `Makefile`, `scripts/run_case.sh`, `scripts/_run_all.sh` a `scripts/wait_ready.sh` |

## Reprodukovateľnosť a limity

Reprodukovateľnosť je podporená:

- fixnou Compose topológiou,
- skriptovaným spúšťaním scenárov,
- samostatným ukladaním logov, PCAP, KPI a proveniencie pre každý beh,
- oddelením `baseline` a `secure` profilov,
- schémovo fixovaným exportom `summary.json`.

Tento projekt je laboratórny testbed. Výsledky sú platné v rámci definovaného Docker prostredia a explicitne zvoleného datasetu. Nejde o produkčný benchmark ani o dôkaz všeobecnej bezpečnosti IoT zariadení.

## Licencia

Repozitár je distribuovaný pod licenciou uvedenou v súbore [LICENSE](LICENSE).
