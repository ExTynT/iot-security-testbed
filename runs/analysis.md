 Container iot-security-testbed-monitor-collector-run-1aaf20cb4fdb Creating 
 Container iot-security-testbed-monitor-collector-run-1aaf20cb4fdb Created 
[GRAF] /runs/figures/fig1_p1_mqtt_kpi.png
[GRAF] /runs/figures/fig2_p2_coap_kpi.png
[GRAF] /runs/figures/fig3_p3_ota_kpi.png
[GRAF] /runs/figures/fig4_cvss_scores.png
[GRAF] /runs/figures/fig5_cia_impact.png

[GRAFY] Vsetky grafy ulozene do: /runs/figures
# IoT Security Testbed - Agregovana analyza vysledkov

## 1. Prehlad runs

Celkovy pocet behov: **18**

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

| Scenar | Pocet replikacii |
|--------|-----------------|
| P1 MQTT Baseline | 3 |
| P1 MQTT Secure | 3 |
| P2 CoAP Baseline | 3 |
| P2 CoAP Secure | 3 |
| P3 OTA Baseline | 3 |
| P3 OTA Secure | 3 |

## 2. Before vs After - KPI tabulka

Priemerne hodnoty KPI napriec replikaciami.

| KPI | Baseline (priemer) | Secure (priemer) | Baseline OK? | Secure OK? |
|---|---|---|---|---|
| MQTT unauth denied | 0 (= 0 (utok uspel)) | 30 (> 0 (odmietnuty)) | OK | OK |
| CoAP plain GETs | 50 (> 0 (plaintext citanie)) | 0 (= 0 (port blokovany)) | OK | OK |
| CoAP plain port blocked | 0 (N/A) | 8.3 (> 0 (iptables OK)) | OK | OK |
| CoAP DTLS failures (wrong PSK) | 0 (N/A) | 5 (> 0 (odmietnuty)) | OK | OK |
| CoAP DTLS OK (spravny PSK) | 0 (N/A) | 1 (>= 1 (DTLS funguje)) | OK | OK |
| OTA evil applied | 1 (> 0 (evil nasadeny)) | 0 (= 0 (zablokovany)) | OK | OK |
| OTA evil blocked | 0 (= 0 (ziadna obrana)) | 1 (> 0 (podpis zamietol)) | OK | OK |

## 3. Vizualizacia KPI (ASCII)

### P1: MQTT unauth denied (Baseline vs Secure)

```
  Baseline [..............................]  0
    Secure [##############################]  30
```

### P2: CoAP plaintext GETs (Baseline vs Secure)

```
  Baseline [##############################]  50
    Secure [..............................]  0
```

### P3: OTA evil applied (Baseline vs Secure)

```
  Baseline [##############################]  1
    Secure [..............................]  0
```

### P3: OTA evil blocked (Baseline vs Secure)

```
  Baseline [..............................]  0
    Secure [##############################]  1
```

## 4. Interpretacia vysledkov

### P1 - MQTT autentifikacia a sifrovanie

Baseline scenar potvrdzuje, ze broker bez TLS/auth umoznuje publikovanie lubovolnemu klientovi (P1_mqtt_unauth_denied = 0). Po nasadeni mitigacie (TLS 8883 + ACL + heslo) broker odmietol vsetkych neautorizovanych klientov (P1_mqtt_unauth_denied > 0), pricom legitímny klient nadal fungoval. Hypoteza P1d potvrdena.

### P2 - CoAP DTLS/PSK a segmentacia

Baseline potvrdzuje plaintext pristup cez port 5683 bez akejkolvek autentifikacie. Secure scenar blokuje port 5683 pomocou iptables (P2_coap_plain_blocked > 0) a vyzaduje DTLS/PSK na porte 5684. Pokus so zlym PSK bol odmietnuty (P2_coap_dtls_failures > 0), spravny PSK bol akceptovany (P2_coap_dtls_ok >= 1). Hypotezy P2a, P2b, P2c potvrdene.

### P3 - OTA integrita (minisign Ed25519)

Baseline potvrdzuje, ze DUT akceptuje firmver z lubovolneho servera bez overenia podpisu (P3_ota_evil_applied > 0). Secure scenar s pinovanym verejnym klucom (minisign Ed25519) odmietol evil firmver (P3_ota_evil_blocked > 0, P3_ota_evil_applied = 0). Hypotezy P3a potvrdena.

## 5. Dopad na CIA a CVSS v4.0 hodnotenie

Skore vypocitane podla CVSS v4.0 Base Score. Vektor pred mitigaciou (Baseline) / po mitigacii (Secure).

| # | Zranitelnost | C | I | A | CVSS v4.0 (pred) | CVSS v4.0 (po) |
|---|-------------|---|---|---|-----------------|----------------|
| P1 | MQTT broker bez auth/TLS (port 1883) | H | H | H | 9.3 (Critical) | 0.0 (None) |
| P2 | CoAP plaintext bez autentifikacie (port 5683) | H | H | L | 8.7 (High) | 0.0 (None) |
| P3 | OTA firmver bez overenia podpisu | H | H | H | 9.3 (Critical) | 0.0 (None) |

> Vektory (CVSS v4.0): AV:N/AC:L/AT:N/PR:N/UI:N. Po mitigacii: utok nie je mozny v definovanom threat modeli testbedu.

## 6. Verzie komponentov (reprodukovatelnost)

| Komponent | Verzia |
|-----------|--------|
| eclipse-mosquitto | 2.0.18 |
| libcoap (server) | 4.3.5 + OpenSSL |
| libcoap (klient Alpine prebuilt) | 4.3.4a (plaintext) |
| nginx | alpine (latest) |
| python (DUT/collector) | 3.12-alpine |
| alpine (attacker/sniffer) | 3.20 |
| minisign | 2.1 (Ed25519) |
| OpenSSL (DTLS klient) | 3.x (Alpine 3.20) |

---
*Generovane automaticky z 18 run(s) v priecinku `/runs`.*
