# IoT Security Testbed

Docker-based testbed pre demonštráciu bezpečnostných zraniteľností v IoT komunikačných protokoloch a efektívnosti mitigácií. Súčasť bakalárskej práce.

## Čo testbed rieši

Tri protokoly, každý v dvoch konfiguráciách (A = zraniteľný baseline, B = mitigovaný secure):

| Protokol | Zraniteľnosť | Mitigácia | KPI |
|----------|-------------|-----------|-----|
| **P1 MQTT** | Broker bez TLS/auth na porte 1883 | TLS 8883 + ACL + heslo | `unauth_denied > 0` |
| **P2 CoAP** | Plaintext UDP bez autentifikácie | DTLS/PSK na 5684 + iptables blok 5683 | `dtls_failures > 0` |
| **P3 OTA** | Firmvér bez overenia podpisu | minisign Ed25519 pinovaný verejný kľúč | `evil_blocked > 0` |

## Požiadavky

| Závislost | Verzia | Poznámka |
|-----------|--------|----------|
| Docker Engine | ≥ 24.0 | alebo Docker Desktop ≥ 4.25 |
| Docker Compose | v2 (plugin) | príkaz `docker compose` (nie `docker-compose`) |
| Bash | ≥ 4.0 | Git Bash / WSL2 na Windows |
| GNU Make | ≥ 3.82 | (`make --version`) |

> **Windows**: Všetky príkazy spúšťaj cez **Git Bash** (nie PowerShell ani cmd).
> minisign binárka je priložená v `tools/minisign/minisign-win64/`.

## Verzie Docker imidžov

| Komponent | Imidž / Verzia |
|-----------|----------------|
| MQTT broker | `eclipse-mosquitto:2.0.18` |
| CoAP server | `alpine:3.20` + libcoap 4.3.5 (OpenSSL DTLS) |
| OTA server (official) | `nginx:alpine` |
| DUT (Device Under Test) | `python:3.12-alpine` + paho-mqtt + minisign |
| Attacker | `alpine:3.20` + mosquitto-clients + vlastný DTLS klient |
| Sniffer | `alpine:3.20` + tcpdump |
| Monitor/Collector | `python:3.12-alpine` |

## Štruktúra projektu

```
iot-security-testbed/
├── docker-compose.yml              # Základná topológia (baseline)
├── docker-compose.mqtt-secure.yml  # Overlay: MQTT TLS+ACL
├── docker-compose.coap-secure.yml  # Overlay: DTLS/PSK + iptables
├── docker-compose.ota-secure.yml   # Overlay: minisign overenie
├── Makefile                        # Ciele: scenáre, replikácie, analýza
├── configs/
│   ├── mqtt/baseline/              # mosquitto.conf (plaintext)
│   ├── mqtt/secure/                # mosquitto.conf + certs + passwd + ACL
│   ├── coap/                       # (prázdny, PSK v .env)
│   └── ota/
│       ├── repo/                   # Legitímny firmvér + manifest
│       └── evil/                   # Evil firmvér + falošný podpis
├── images/
│   ├── attacker/                   # Dockerfile + coap_dtls_psk.c
│   ├── coap-server/                # Dockerfile (libcoap 4.3.5 + iptables)
│   ├── dut/                        # Dockerfile + dut.py
│   ├── monitor-collector/          # Dockerfile + collector.py
│   └── sniffer/                    # Dockerfile (tcpdump)
├── scripts/
│   ├── new_run.sh                  # Inicializuje nový run (RUN_ID, .env, adresáre)
│   ├── mqtt_baseline_attack.sh
│   ├── mqtt_secure_attack_unauth.sh
│   ├── mqtt_secure_control_auth.sh
│   ├── coap_baseline_attack.sh
│   ├── coap_secure_attack_plain_should_fail.sh
│   ├── coap_secure_attack_wrong_psk.sh
│   ├── coap_secure_attack_ok_psk.sh
│   ├── ota_attack_evil.sh
│   ├── analyze_results.py          # Agregovaná analýza všetkých runs/
│   └── gen_mqtt_passwd.sh
└── runs/                           # Výstupy (gitignored, len .gitkeep)
    └── <RUN_ID>/
        ├── logs/    # *.log zo všetkých kontajnerov
        ├── pcap/    # *.pcap (tcpdump)
        ├── results/ # summary.json, report.md
        └── state/   # scenario.txt, version.txt
```

## Rýchly štart

### 1. Zostav imidže (raz)

```bash
cd iot-security-testbed
make build
```

### 2. Vygeneruj MQTT heslo (raz)

```bash
make gen-passwd
```

### 3. Spusti jednotlivé scenáre

```bash
make mqtt-baseline    # P1: MQTT bez ochrán
make mqtt-secure      # P1: MQTT TLS+ACL+heslo

make coap-baseline    # P2: CoAP bez DTLS
make coap-secure      # P2: CoAP DTLS/PSK + firewall

make ota-baseline     # P3: OTA bez podpisu
make ota-secure       # P3: OTA minisign
```

Každý cieľ automaticky:
1. Inicializuje nový `RUN_ID` a adresáre
2. Spustí Docker stack
3. Spustí útočné skripty
4. Zberie logy a vygeneruje `summary.json` + `report.md`
5. Zastaví stack

### 4. Replikácie (≥ 3 behy pre dôveryhodnosť)

```bash
make replicate-mqtt N=3    # 3× mqtt-baseline + mqtt-secure
make replicate-coap N=3    # 3× coap-baseline + coap-secure
make replicate-ota  N=3    # 3× ota-baseline  + ota-secure

# alebo všetko naraz:
make replicate-all N=3
```

### 5. Agregovaná analýza výsledkov

```bash
make analyze
# → runs/analysis.md (Before/After tabuľka, ASCII grafy, CVSS)
```

## Výsledky každého behu

Po každom `make <scenár>`:

```
runs/<RUN_ID>/
├── logs/mqtt.log          # Mosquitto server log
├── logs/coap.log          # libcoap server log
├── logs/dut.log           # DUT aplikačný log
├── logs/attacks.log       # KPI markery z útočných skriptov
├── pcap/mqtt.pcap         # Sieťová zachytávka MQTT
├── pcap/coap.pcap         # Sieťová zachytávka CoAP
├── pcap/ota.pcap          # HTTP OTA (official)
├── pcap/ota_evil.pcap     # HTTP OTA (evil)
├── results/summary.json   # Strojovo čitateľné KPI
├── results/report.md      # Markdown správa
└── state/scenario.txt     # Názov scenára
```

### Príklad summary.json (coap-secure)

```json
{
  "scenario": "coap-secure",
  "kpi": {
    "P1_mqtt_unauth_denied":  0,
    "P2_coap_plain_gets":     0,
    "P2_coap_plain_blocked":  1,
    "P2_coap_dtls_failures":  1,
    "P2_coap_dtls_ok":        1,
    "P3_ota_evil_applied":    0,
    "P3_ota_evil_blocked":    0
  }
}
```

## Technické detaily

### MQTT Secure
- Mosquitto 2.0.18 na porte 8883 s TLS (self-signed CA)
- ACL: `device01` môže len `write telemetry/#` a `read cmd/#`
- Plaintext port 1883 je v secure konfigurácii nedostupný

### CoAP Secure
- libcoap 4.3.5 skompilovany s OpenSSL (DTLS/PSK), port 5684
- iptables `DROP udp --dport 5683` vo vnútri kontajnera (cap_add: NET_ADMIN)
- Vlastný DTLS klient `coap_dtls_psk.c` (OpenSSL priamo) – libcoap v4.3.5 má bug
  v klientskom DTLS PSK (`SSL_set_psk_client_callback` nikdy nie je volaný)

### OTA Secure
- minisign Ed25519 podpis manifestu (`manifest.json.minisig`)
- DUT má pinovaný verejný kľúč cez `MINISIGN_PUBKEY` env premenná
- Evil firmvér má falošný `.minisig` → overenie zlyhá

## Troubleshooting

| Problém | Riešenie |
|---------|---------|
| `make mqtt-secure` zlyhá s "Chyba: spusti gen-passwd" | `make gen-passwd` |
| `make ota-secure` zlyhá – chýba minisign.pub | Spustí sa automaticky, skontroluj `tools/minisign/` |
| DTLS handshake vždy zlyhá | Skontroluj, či je imidž `coap-server` zostavený s OpenSSL: `make build` |
| Port 5683 nie je blokovaný | Kontajner potrebuje `cap_add: NET_ADMIN` – skontroluj overlay |
| OTA evil nie je blokovaný v secure | `MINISIGN_PUBKEY` musí byť nastavený pred štartom DUT |
| `docker compose exec` chyba | Stack nie je spustený – spusti `make <scenár>` alebo `docker compose up -d` |

## Reprodukovateľnosť (pre obhajobu)

Celý testbed je reprodukovateľný na ľubovoľnom stroji s Docker:

```bash
git clone <repo>
cd iot-security-testbed
make build
make gen-passwd
make replicate-all N=3
make analyze
```

Výsledky budú v `runs/` a agregovaná správa v `runs/analysis.md`.

> Verzie sú pinované v Dockerfiles (`FROM alpine:3.20`, `FROM python:3.12-alpine`,
> `eclipse-mosquitto:2.0.18`). libcoap je stiahnutý ako tarball v4.3.5.
