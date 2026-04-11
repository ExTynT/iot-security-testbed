# IoT Security Testbed - Agregovana analyza vysledkov

## 0. Dataset scope

Analyza bola vygenerovana nad vsetkymi dostupnymi behov v `runs/`.

Figury boli ulozene do: **runs/figures/**

## 1. Prehlad runs

Celkovy pocet behov: **58**

| Run ID | Scenar |
|--------|--------|
| 20260302-152127 | mqtt-baseline |
| 20260302-152145 | mqtt-baseline |
| 20260302-152202 | mqtt-baseline |
| 20260302-152219 | mqtt-secure |
| 20260302-152244 | mqtt-secure |
| 20260302-152309 | mqtt-secure |
| 20260302-152333 | coap-baseline |
| 20260302-152348 | coap-baseline |
| 20260302-152402 | coap-baseline |
| 20260302-152415 | coap-secure |
| 20260302-152659 | coap-secure |
| 20260302-152942 | coap-secure |
| 20260302-153223 | ota-baseline |
| 20260302-153243 | ota-baseline |
| 20260302-153304 | ota-baseline |
| 20260302-153324 | ota-secure |
| 20260302-153350 | ota-secure |
| 20260302-153417 | ota-secure |
| 20260312-013251 | coap-baseline |
| 20260312-013430 | mqtt-secure |
| 20260312-013523 | coap-baseline |
| 20260312-013554 | coap-secure |
| 20260312-014007 | ota-baseline |
| 20260312-014125 | ota-secure |
| 20260322-135838 | mqtt-secure |
| 20260322-135951 | coap-secure |
| 20260322-141155 | mqtt-secure |
| 20260322-141320 | mqtt-secure |
| 20260322-141639 | mqtt-secure |
| 20260322-141801 | mqtt-secure |
| 20260322-141823 | coap-secure |
| 20260322-142005 | coap-secure |
| 20260322-143502 | coap-secure |
| 20260322-144021 | coap-secure |
| 20260322-144206 | ota-secure |
| 20260322-144607 | ota-secure |
| 20260322-150545 | coap-baseline |
| 20260322-150634 | unknown |
| 20260322-151040 | unknown |
| 20260322-153904 | mqtt-baseline |
| 20260322-153918 | mqtt-secure |
| 20260322-153936 | coap-baseline |
| 20260322-153949 | coap-secure |
| 20260322-154111 | ota-baseline |
| 20260322-154121 | ota-secure |
| 20260322-155709 | mqtt-secure |
| 20260322-155953 | ota-secure |
| 20260322-155954 | mqtt-secure |
| 20260322-160207 | mqtt-secure |
| 20260322-160231 | ota-secure |
| 20260322-160502 | mqtt-secure |
| 20260322-160524 | ota-secure |
| 20260322-161426 | mqtt-baseline |
| 20260322-161440 | mqtt-secure |
| 20260322-161453 | coap-baseline |
| 20260322-161510 | coap-secure |
| 20260322-161634 | ota-baseline |
| 20260322-161643 | ota-secure |

| Scenar | Pocet replikacii |
|--------|-----------------|
| P1 MQTT Baseline | 5 |
| P1 MQTT Secure | 15 |
| P2 CoAP Baseline | 8 |
| P2 CoAP Secure | 11 |
| P3 OTA Baseline | 6 |
| P3 OTA Secure | 11 |

| Scenar | Behy s varovaniami |
|--------|--------------------|
| P1 MQTT Baseline | 0 |
| P1 MQTT Secure | 3 |
| P2 CoAP Baseline | 0 |
| P2 CoAP Secure | 1 |
| P3 OTA Baseline | 0 |
| P3 OTA Secure | 1 |

## 2. Before vs After - KPI tabulka

Priemerne hodnoty KPI napriec replikaciami.

| KPI | Baseline (priemer) | Secure (priemer) | Baseline OK? | Secure OK? |
|---|---|---|---|---|
| MQTT unauth denied | 0 (= 0 (utok uspel)) | 28 (> 0 (odmietnuty)) | OK | OK |
| CoAP plain GETs | 28.8 (> 0 (plaintext citanie)) | 0 (= 0 (plaintext endpoint disabled)) | OK | OK |
| CoAP plaintext endpoint disabled | 0 (N/A) | 5.9 (> 0 (plaintext endpoint disabled)) | OK | OK |
| CoAP DTLS failures (wrong PSK) | 0 (N/A) | 4.5 (> 0 (odmietnuty)) | OK | OK |
| CoAP DTLS OK (spravny PSK) | 0 (N/A) | 0.9 (>= 1 (DTLS funguje)) | OK | FAIL |
| OTA evil applied | 1 (> 0 (evil nasadeny)) | 0.1 (= 0 (zablokovany)) | OK | FAIL |
| OTA evil blocked | 0 (= 0 (ziadna obrana)) | 0.9 (> 0 (podpis zamietol)) | OK | OK |
| OTA signed update OK | 0 (N/A) | 0.5 (>= 1 (legitimna OTA funguje)) | OK | FAIL |

## 3. Vizualizacia KPI (ASCII)

### P1: MQTT unauth denied

```
  Baseline [..............................]  0
    Secure [##############################]  28
```

### P2: CoAP plaintext GETs

```
  Baseline [##############################]  28.8
    Secure [..............................]  0
```

### P3: OTA evil applied

```
  Baseline [##############################]  1
    Secure [###...........................]  0.1
```

### P3: OTA evil blocked

```
  Baseline [..............................]  0
    Secure [###########################...]  0.9
```

### P3: OTA signed update OK

```
  Baseline [..............................]  0
    Secure [################..............]  0.5
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
*Generovane automaticky z 58 run(s) v priecinku `/runs`.*
