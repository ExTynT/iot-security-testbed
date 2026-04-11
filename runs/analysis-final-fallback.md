# IoT Security Testbed - Agregovana analyza vysledkov

## 0. Dataset scope

Analyza bola vygenerovana nad explicitne zvolenou finalnou mnozinou behov.

Vybrate run IDs: **20260322-161426, 20260322-161440, 20260322-161453, 20260322-161510, 20260322-161634, 20260322-161643**

Figury boli ulozene do: **runs/figures-final-fallback/**

## 1. Prehlad runs

Celkovy pocet behov: **6**

| Run ID | Scenar |
|--------|--------|
| 20260322-161426 | mqtt-baseline |
| 20260322-161440 | mqtt-secure |
| 20260322-161453 | coap-baseline |
| 20260322-161510 | coap-secure |
| 20260322-161634 | ota-baseline |
| 20260322-161643 | ota-secure |

| Scenar | Pocet replikacii |
|--------|-----------------|
| P1 MQTT Baseline | 1 |
| P1 MQTT Secure | 1 |
| P2 CoAP Baseline | 1 |
| P2 CoAP Secure | 1 |
| P3 OTA Baseline | 1 |
| P3 OTA Secure | 1 |

| Scenar | Behy s varovaniami |
|--------|--------------------|
| P1 MQTT Baseline | 0 |
| P1 MQTT Secure | 0 |
| P2 CoAP Baseline | 0 |
| P2 CoAP Secure | 0 |
| P3 OTA Baseline | 0 |
| P3 OTA Secure | 0 |

## 2. Before vs After - KPI tabulka

Priemerne hodnoty KPI napriec replikaciami.

| KPI | Baseline (priemer) | Secure (priemer) | Baseline OK? | Secure OK? |
|---|---|---|---|---|
| MQTT unauth denied | 0 (= 0 (utok uspel)) | 30 (> 0 (odmietnuty)) | OK | OK |
| CoAP plain GETs | 10 (> 0 (plaintext citanie)) | 0 (= 0 (plaintext endpoint disabled)) | OK | OK |
| CoAP plaintext endpoint disabled | 0 (N/A) | 3 (> 0 (plaintext endpoint disabled)) | OK | OK |
| CoAP DTLS failures (wrong PSK) | 0 (N/A) | 5 (> 0 (odmietnuty)) | OK | OK |
| CoAP DTLS OK (spravny PSK) | 0 (N/A) | 1 (>= 1 (DTLS funguje)) | OK | OK |
| OTA evil applied | 1 (> 0 (evil nasadeny)) | 0 (= 0 (zablokovany)) | OK | OK |
| OTA evil blocked | 0 (= 0 (ziadna obrana)) | 1 (> 0 (podpis zamietol)) | OK | OK |
| OTA signed update OK | 0 (N/A) | 1 (>= 1 (legitimna OTA funguje)) | OK | OK |

## 3. Vizualizacia KPI (ASCII)

### P1: MQTT unauth denied

```
  Baseline [..............................]  0
    Secure [##############################]  30
```

### P2: CoAP plaintext GETs

```
  Baseline [##############################]  10
    Secure [..............................]  0
```

### P3: OTA evil applied

```
  Baseline [##############################]  1
    Secure [..............................]  0
```

### P3: OTA evil blocked

```
  Baseline [..............................]  0
    Secure [##############################]  1
```

### P3: OTA signed update OK

```
  Baseline [..............................]  0
    Secure [##############################]  1
```

## 4. Interpretacia vysledkov

### P1 - MQTT autentifikacia a sifrovanie

Baseline scenar potvrdzuje, ze broker bez TLS/auth umoznuje publikovanie lubovolnemu klientovi (P1_mqtt_unauth_denied = 0). Po nasadeni mitigacie (TLS 8883 + ACL + heslo) broker odmietol neautorizovanych klientov (P1_mqtt_unauth_denied > 0), pricom kontrolne autorizovane publish/subscribe operacie nadalej fungovali.

### P2 - CoAP DTLS/PSK a secure-only endpoint

Baseline potvrdzuje plaintext pristup cez port 5683 bez autentifikacie. Secure scenar neexponuje plaintext endpoint na porte 5683 (P2_coap_plain_blocked > 0) a vyzaduje DTLS/PSK na porte 5684. Pokus so zlym PSK bol odmietnuty (P2_coap_dtls_failures > 0), spravny PSK bol akceptovany (P2_coap_dtls_ok >= 1).

### P3 - OTA integrita (minisign Ed25519)

Baseline potvrdzuje, ze DUT akceptuje firmver z lubovolneho servera bez overenia podpisu (P3_ota_evil_applied > 0). Secure scenar s pinovanym verejnym klucom zachoval funkcnost legitimnej podpisanej OTA aktualizacie (P3_ota_signed_ok >= 1) a zaroven odmietol evil firmver (P3_ota_evil_blocked > 0, P3_ota_evil_applied = 0).

## 5. Dopad na CIA a CVSS v4.0 hodnotenie

Poznamka: CVSS a CIA su analyticky odhad autora, nie automaticky merane KPI.

Skore je uvedene ako porovnanie stavu pred mitigaciou a po mitigacii.

| # | Zranitelnost | C | I | A | CVSS v4.0 (pred) | CVSS v4.0 (po) |
|---|-------------|---|---|---|-----------------|----------------|
| P1 | MQTT broker bez auth/TLS (port 1883) | H | H | L | 9.3 (Critical) | 2.1 (Low) |
| P2 | CoAP plaintext bez autentifikacie (port 5683) | L | L | L | 5.3 (Medium) | 3.1 (Low) |
| P3 | OTA firmver bez overenia podpisu | H | H | L | 9.2 (Critical) | 2.1 (Low) |

> Rezidualne skore po mitigacii je analyticky odhad: P1=2.1 (brute-force hesla / TLS handshake flood), P2=3.1 (konzervativny odhad rezidualneho dopadu mimo priamo testovanej operacie), P3=2.1 (rollback attack bez version-pinningu).

## 6. Verzie komponentov (reprodukovatelnost)

| Komponent | Verzia |
|-----------|--------|
| eclipse-mosquitto | 2.0.18 |
| libcoap (server) | 4.3.5 + OpenSSL |
| libcoap (klient Alpine prebuilt) | 4.3.4a (plaintext) |
| nginx | sha256:f46cb72c7df0... |
| python (DUT/collector) | 3.12-alpine |
| alpine (attacker/sniffer) | 3.20 |
| minisign | 2.1 (Ed25519) |
| OpenSSL (DTLS klient) | 3.x (Alpine 3.20) |

---
*Generovane automaticky z 6 explicitne zvolenych run(s) v priecinku `/runs` so scope `20260322-161426, 20260322-161440, 20260322-161453, 20260322-161510, 20260322-161634, 20260322-161643`.*
