import os, json, re, time

LOGS    = "/logs"
RESULTS = "/results"
STATE   = "/state"

def read(path):
    try:
        return open(path, "r", errors="ignore").read()
    except:
        return ""

scenario = read(f"{STATE}/scenario.txt").strip() or "unknown"

mqtt    = read(f"{LOGS}/mqtt.log")
coap    = read(f"{LOGS}/coap.log")
dut     = read(f"{LOGS}/dut.log")
ota     = read(f"{LOGS}/ota_access.log")
attacks = read(f"{LOGS}/attacks.log")

# ─── Surové počty ─────────────────────────────────────────────────────────────
mqtt_published      = len(re.findall(r"PUBLISH", mqtt, re.I))
mqtt_unauth_success = len(re.findall(r"P1_mqtt_unauth_success", attacks))
# P1: z Mosquitto logu ALEBO z attacks.log markera (ak TLS error bráni server-side logu)
mqtt_denied    = (len(re.findall(r"not authorised|Connection error", mqtt, re.I)) or
                  len(re.findall(r"P1_mqtt_unauth_denied", attacks)))

# P2: plain CoAP gets – z attacks.log markera (baseline) alebo server logu (fallback)
coap_plain_received  = (len(re.findall(r"P2_coap_plain_gets", attacks)) or
                        len(re.findall(r"v:1 t:CON", coap, re.I)))
coap_dtls_failures   = len(re.findall(r"P2_coap_dtls_failure", attacks))
coap_plain_blocked   = len(re.findall(r"P2_coap_plain_blocked", attacks))
coap_plain_accessible = len(re.findall(r"P2_coap_plain_accessible", attacks))
coap_dtls_ok         = len(re.findall(r"P2_coap_dtls_ok", attacks))

ota_requests = len(re.findall(r"GET", ota))
ota_applied  = len(re.findall(r"aplikované", dut, re.I))
ota_blocked  = len(re.findall(r"ZAMIETNUTÁ", dut, re.I))

# ─── KPI podľa definícií z bakalárskej práce ──────────────────────────────────
# P1 MQTT  – Baseline: denied=0 (útočník uspel) | Secure: denied>0 (odmietnutý)
# P2 CoAP  – Baseline: plain_gets>0 (čítanie bez DTLS) | Secure: plain_blocked=1
#            Secure:   dtls_failures>0 (zlý PSK odmietnutý)
# P3 OTA   – Baseline: applied>0 (evil nasadený) | Secure: blocked>0 (odmietnutý)

kpi = {
    "P1_mqtt_unauth_denied":   mqtt_denied,
    "P1_mqtt_unauth_success":  mqtt_unauth_success,
    "P2_coap_plain_gets":      coap_plain_received,
    "P2_coap_plain_blocked":   coap_plain_blocked,
    "P2_coap_dtls_failures":   coap_dtls_failures,
    "P2_coap_dtls_ok":         coap_dtls_ok,
    "P3_ota_evil_applied":     ota_applied,
    "P3_ota_evil_blocked":     ota_blocked,
}

summary = {
    "scenario": scenario,
    "kpi": kpi,
    "raw": {
        "mqtt": {
            "unauth_success": mqtt_unauth_success,
            "denied":         mqtt_denied,
            "published":      mqtt_published,
        },
        "coap": {
            "plain_gets_received":  coap_plain_received,
            "plain_blocked":        coap_plain_blocked,
            "plain_accessible":     coap_plain_accessible,
            "dtls_failures":        coap_dtls_failures,
            "dtls_ok":              coap_dtls_ok,
        },
        "ota": {
            "http_requests": ota_requests,
        },
        "dut": {
            "ota_applied": ota_applied,
            "ota_blocked": ota_blocked,
        },
    },
}

os.makedirs(RESULTS, exist_ok=True)
json_out = json.dumps(summary, indent=2, ensure_ascii=False)
open(f"{RESULTS}/summary.json", "w").write(json_out)

report = f"""# IoT Security Testbed – Run Report

**Scenár:** `{scenario}`

## KPI

| Metrika | Hodnota | Interpretácia |
|---------|---------|---------------|
| P1 mqtt_unauth_denied  | {kpi['P1_mqtt_unauth_denied']} | Baseline=0 (útočník uspel) / Secure>0 (odmietnutý) |
| P2 coap_plain_gets     | {kpi['P2_coap_plain_gets']} | Baseline>0 (čítanie bez auth) / Secure=0 (port blokovaný) |
| P2 coap_plain_blocked  | {kpi['P2_coap_plain_blocked']} | Secure=1 (iptables blokoval port 5683) |
| P2 coap_dtls_failures  | {kpi['P2_coap_dtls_failures']} | Secure>0 (zlý PSK odmietnutý) |
| P2 coap_dtls_ok        | {kpi['P2_coap_dtls_ok']} | Secure=1 (správny PSK akceptovaný) |
| P3 ota_evil_applied    | {kpi['P3_ota_evil_applied']} | Baseline>0 (evil nasadený) / Secure=0 |
| P3 ota_evil_blocked    | {kpi['P3_ota_evil_blocked']} | Secure>0 (podpis odmietnutý) |

## Raw dáta

```json
{json_out}
```
"""

open(f"{RESULTS}/report.md", "w").write(report)
print("collector: summary.json a report.md vytvorené")
print(f"KPI: {json.dumps(kpi, ensure_ascii=False)}")

# ─── Per-run KPI graf ─────────────────────────────────────────────────────────
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches

    # Relevantné KPI + podmienka správneho výsledku pre každý scenár
    SCENARIO_KPI = {
        "mqtt-baseline": [
            ("P1_mqtt_unauth_success", "Uspesne utoky\n(ocakavane: 30)",  lambda v: v == 30),
            ("P1_mqtt_unauth_denied",  "Odmietnutia\n(ocakavane: 0)",     lambda v: v == 0),
        ],
        "mqtt-secure": [
            ("P1_mqtt_unauth_denied",  "Odmietnutia\n(ocakavane: 30)",    lambda v: v == 30),
            ("P1_mqtt_unauth_success", "Uspesne utoky\n(ocakavane: 0)",   lambda v: v == 0),
        ],
        "coap-baseline": [
            ("P2_coap_plain_gets",     "Plaintext GETs\n(ocakavane: >0)", lambda v: v > 0),
        ],
        "coap-secure": [
            ("P2_coap_plain_blocked",  "Port 5683 blokovany\n(ocakavane: >0)",  lambda v: v > 0),
            ("P2_coap_dtls_failures",  "DTLS zly PSK odmietnuty\n(ocakavane: 5)", lambda v: v == 5),
            ("P2_coap_dtls_ok",        "DTLS spravny PSK OK\n(ocakavane: 1)",   lambda v: v >= 1),
        ],
        "ota-baseline": [
            ("P3_ota_evil_applied",    "Evil firmver aplikovany\n(ocakavane: 1)", lambda v: v > 0),
        ],
        "ota-secure": [
            ("P3_ota_evil_blocked",    "Evil firmver zablokovany\n(ocakavane: 1)", lambda v: v > 0),
            ("P3_ota_evil_applied",    "Evil firmver aplikovany\n(ocakavane: 0)",  lambda v: v == 0),
        ],
    }

    kpi_cfg = SCENARIO_KPI.get(scenario, [])
    if kpi_cfg:
        labels = [lbl  for _, lbl, _  in kpi_cfg]
        values = [kpi.get(k, 0) for k, _, _ in kpi_cfg]
        colors = ["#27AE60" if ok_fn(kpi.get(k, 0)) else "#E74C3C"
                  for k, _, ok_fn in kpi_cfg]

        fig_h = max(3.0, len(labels) * 1.4 + 1.2)
        fig, ax = plt.subplots(figsize=(9, fig_h))
        bars = ax.barh(labels, values, color=colors, edgecolor="white",
                       linewidth=1.5, height=0.55)

        xmax = max(values + [1]) * 1.45
        ax.set_xlim(0, xmax)
        for bar, val in zip(bars, values):
            ax.text(val + xmax * 0.02, bar.get_y() + bar.get_height() / 2,
                    str(int(val)), va="center", ha="left",
                    fontsize=12, fontweight="bold")

        ax.set_xlabel("KPI hodnota", fontsize=11)
        ax.set_title(f"KPI výsledky – {scenario}", fontsize=13, fontweight="bold")
        ax.tick_params(axis="y", labelsize=10)

        ok_p   = mpatches.Patch(color="#27AE60", label="OK – ocakavana hodnota")
        fail_p = mpatches.Patch(color="#E74C3C", label="FAIL – neocakavana hodnota")
        ax.legend(handles=[ok_p, fail_p], fontsize=9, loc="lower right")

        for sp in ["top", "right"]:
            ax.spines[sp].set_visible(False)
        ax.grid(True, axis="x", alpha=0.3, linestyle="--")

        plt.tight_layout()
        plt.savefig(f"{RESULTS}/fig_kpi.png", dpi=150,
                    bbox_inches="tight", facecolor="white")
        plt.close()
        print(f"collector: fig_kpi.png ulozeny do {RESULTS}/")

except ImportError:
    pass
except Exception as e:
    print(f"collector: [WARN] Graf sa nepodarilo vygenerovat: {e}")

time.sleep(2)
