import json
import os
import re
import time

LOGS = "/logs"
RESULTS = "/results"
STATE = "/state"


def read(path, warn_missing=True):
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except FileNotFoundError:
        if warn_missing:
            import sys

            print(f"[WARN] Chybajuci subor: {path}", file=sys.stderr, flush=True)
        return ""
    except Exception as e:
        import sys

        print(f"[WARN] Chyba citania {path}: {e}", file=sys.stderr, flush=True)
        return ""


def read_optional(path):
    return read(path, warn_missing=False)


def file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


scenario = read(f"{STATE}/scenario.txt").strip() or "unknown"

mqtt = read_optional(f"{LOGS}/mqtt.log")
coap = read_optional(f"{LOGS}/coap.log")
dut = read_optional(f"{LOGS}/dut.log")
ota = read_optional(f"{LOGS}/ota_access.log")
ota_evil = read_optional(f"{LOGS}/ota_evil_access.log")
attacks = read_optional(f"{LOGS}/attacks.log")
mqtt_control = read_optional(f"{LOGS}/mqtt_control.log")
coap_plain_probe = read_optional(f"{LOGS}/coap_plain_probe.log")
coap_baseline_probe = read_optional(f"{LOGS}/coap_baseline_probe.log")
coap_dtls_wrong = read_optional(f"{LOGS}/coap_dtls_wrong_psk.log")
coap_dtls_ok_log = read_optional(f"{LOGS}/coap_dtls_ok.log")
ota_control = read_optional(f"{LOGS}/ota_control.log")
ota_attack = read_optional(f"{LOGS}/ota_attack.log")
state_version = read_optional(f"{STATE}/version.txt").strip()

warnings = []
if scenario == "mqtt-secure" and not mqtt_control:
    warnings.append("mqtt_control_log_missing")
if scenario == "mqtt-secure" and mqtt_control and not re.search(r"AUTH_WRITE_OK", mqtt_control, re.I):
    warnings.append("mqtt_auth_write_not_confirmed")
if scenario == "mqtt-secure" and mqtt_control and not re.search(r"AUTH_READ_OK", mqtt_control, re.I):
    warnings.append("mqtt_auth_read_not_confirmed")
if scenario == "coap-secure" and not coap_plain_probe:
    warnings.append("coap_plain_probe_log_missing")
if scenario == "coap-secure" and not coap_dtls_wrong:
    warnings.append("coap_dtls_wrong_psk_log_missing")
if scenario == "coap-secure" and not coap_dtls_ok_log:
    warnings.append("coap_dtls_ok_log_missing")
if scenario in {"ota-baseline", "ota-secure"} and not ota:
    warnings.append("ota_access_log_missing")
if scenario in {"ota-baseline", "ota-secure"} and not ota_evil:
    warnings.append("ota_evil_access_log_missing")
if scenario == "ota-secure" and not ota_control:
    warnings.append("ota_control_log_missing")
if scenario in {"ota-baseline", "ota-secure"} and not ota_attack:
    warnings.append("ota_attack_log_missing")

# MQTT
mqtt_published = len(re.findall(r"PUBLISH", mqtt, re.I))
mqtt_unauth_success_log = len(re.findall(r"Received PUBLISH .*'cmd/ota'", mqtt, re.I))
mqtt_unauth_success_marker = len(re.findall(r"P1_mqtt_unauth_success", attacks))
mqtt_denied_connack = len(re.findall(r"Sending CONNACK .* \(0, 5\)", mqtt, re.I))
mqtt_denied_marker = len(re.findall(r"P1_mqtt_unauth_denied", attacks))
mqtt_auth_write_ok = len(re.findall(r"Received PUBLISH .*'cmd/test'", mqtt, re.I))
mqtt_auth_read_ok = len(re.findall(r"AUTH_READ_OK", mqtt_control, re.I))

if scenario.startswith("mqtt-"):
    mqtt_unauth_success = mqtt_unauth_success_marker or mqtt_unauth_success_log
    mqtt_denied = mqtt_denied_marker or mqtt_denied_connack
else:
    mqtt_unauth_success = 0
    mqtt_denied = 0

# CoAP
coap_plain_accessible = len(re.findall(r"^ACCESSIBLE\b", coap_plain_probe, re.M))
coap_baseline_accessible = len(re.findall(r"^ACCESSIBLE\b", coap_baseline_probe, re.M))
coap_plain_blocked_log = len(re.findall(r"^BLOCKED\b", coap_plain_probe, re.M))
coap_plain_received_server = len(re.findall(r"v:1 t:CON", coap, re.I))
coap_plain_received = (
    coap_plain_accessible
    if scenario == "coap-secure"
    else (coap_baseline_accessible or coap_plain_received_server or len(re.findall(r"P2_coap_plain_gets", attacks)))
)
coap_dtls_failures = len(re.findall(r"^FAIL\b", coap_dtls_wrong, re.M)) or len(
    re.findall(r"P2_coap_dtls_failure", attacks)
)
coap_plain_blocked = coap_plain_blocked_log or len(re.findall(r"P2_coap_plain_blocked", attacks))
coap_plain_accessible_marked = len(re.findall(r"P2_coap_plain_accessible", attacks))
if not coap_plain_accessible:
    coap_plain_accessible = coap_plain_accessible_marked
coap_dtls_ok = len(re.findall(r"CoAP response 2\.05", coap_dtls_ok_log, re.I)) or len(
    re.findall(r"P2_coap_dtls_ok", attacks)
)

# OTA
ota_requests = len(re.findall(r"GET /", ota))
ota_evil_requests = len(re.findall(r"GET /", ota_evil))
ota_control_signed_ok = len(re.findall(r"^SIGNED_OK\b", ota_control, re.M))
ota_control_before = re.search(r"^BEFORE_VERSION=(.+)$", ota_control, re.M)
ota_control_after = re.search(r"^AFTER_VERSION=(.+)$", ota_control, re.M)
ota_control_http_before = re.search(r"^OFFICIAL_HTTP_BEFORE=(\d+)$", ota_control, re.M)
ota_control_http_after = re.search(r"^OFFICIAL_HTTP_AFTER=(\d+)$", ota_control, re.M)
ota_control_before_version = ota_control_before.group(1).strip() if ota_control_before else ""
ota_control_after_version = ota_control_after.group(1).strip() if ota_control_after else ""
ota_control_http_delta = max(
    int(ota_control_http_after.group(1)) - int(ota_control_http_before.group(1)),
    0,
) if ota_control_http_before and ota_control_http_after else 0
ota_attack_before = re.search(r"^BEFORE_VERSION=(.+)$", ota_attack, re.M)
ota_attack_after = re.search(r"^AFTER_VERSION=(.+)$", ota_attack, re.M)
ota_attack_http_before = re.search(r"^EVIL_HTTP_BEFORE=(\d+)$", ota_attack, re.M)
ota_attack_http_after = re.search(r"^EVIL_HTTP_AFTER=(\d+)$", ota_attack, re.M)
ota_before_version = ota_attack_before.group(1).strip() if ota_attack_before else ""
ota_after_version = ota_attack_after.group(1).strip() if ota_attack_after else ""
ota_evil_http_delta = max(
    int(ota_attack_http_after.group(1)) - int(ota_attack_http_before.group(1)),
    0,
) if ota_attack_http_before and ota_attack_http_after else 0
ota_attack_new_dut = re.search(r"DUT_NEW_BEGIN\s*(.*?)\s*DUT_NEW_END", ota_attack, re.S)
ota_attack_new_dut_text = ota_attack_new_dut.group(1) if ota_attack_new_dut else ""
ota_applied = 1 if (
    ota_before_version
    and ota_after_version
    and ota_before_version != ota_after_version
    and ota_evil_http_delta > 0
) else 0
ota_blocked = 1 if (
    ota_evil_http_delta > 0 and re.search(r"ZAMIETNUT|NEPLATN", ota_attack_new_dut_text, re.I)
) else 0
ota_signed_ok = 1 if (
    ota_control_signed_ok
    and ota_control_before_version
    and ota_control_after_version
    and ota_control_before_version != ota_control_after_version
    and ota_control_http_delta > 0
) else 0

kpi = {
    "P1_mqtt_unauth_denied": mqtt_denied,
    "P1_mqtt_unauth_success": mqtt_unauth_success,
    "P2_coap_plain_gets": coap_plain_received,
    "P2_coap_plain_blocked": coap_plain_blocked,
    "P2_coap_dtls_failures": coap_dtls_failures,
    "P2_coap_dtls_ok": coap_dtls_ok,
    "P3_ota_evil_applied": ota_applied,
    "P3_ota_evil_blocked": ota_blocked,
    "P3_ota_signed_ok": ota_signed_ok,
}

summary = {
    "scenario": scenario,
    "kpi": kpi,
    "warnings": warnings,
    "evidence": {
        "P1_mqtt_unauth_success": "attacks.log marker" if mqtt_unauth_success_marker else "mqtt.log cmd/ota publish",
        "P1_mqtt_unauth_denied": "attacks.log marker" if mqtt_denied_marker else "mqtt.log CONNACK(0,5)",
        "P2_coap_plain_gets": "coap_baseline_probe.log or coap.log",
        "P2_coap_plain_blocked": "coap_plain_probe.log",
        "P2_coap_dtls_failures": "coap_dtls_wrong_psk.log",
        "P2_coap_dtls_ok": "coap_dtls_ok.log",
        "P3_ota_evil_applied": "ota_attack.log before/after version + ota_evil access delta",
        "P3_ota_evil_blocked": "ota_attack.log new DUT lines + ota_evil access delta",
        "P3_ota_signed_ok": "ota_control.log signed_ok + official access delta",
    },
    "artifacts": {
        "pcap_bytes": {
            "mqtt": file_size("/pcap/mqtt.pcap"),
            "coap": file_size("/pcap/coap.pcap"),
            "ota": file_size("/pcap/ota.pcap"),
            "ota_evil": file_size("/pcap/ota_evil.pcap"),
        },
        "logs_present": {
            "mqtt_log": bool(mqtt),
            "coap_log": bool(coap),
            "dut_log": bool(dut),
            "ota_access_log": bool(ota),
            "ota_evil_access_log": bool(ota_evil),
        },
    },
    "raw": {
        "mqtt": {
            "unauth_success": mqtt_unauth_success,
            "denied": mqtt_denied,
            "published": mqtt_published,
            "auth_write_ok": mqtt_auth_write_ok,
            "auth_read_ok": mqtt_auth_read_ok,
        },
        "coap": {
            "plain_gets_received": coap_plain_received,
            "plain_blocked": coap_plain_blocked,
            "plain_accessible": coap_plain_accessible,
            "baseline_accessible": coap_baseline_accessible,
            "plain_gets_server_log": coap_plain_received_server,
            "dtls_failures": coap_dtls_failures,
            "dtls_ok": coap_dtls_ok,
        },
        "ota": {
            "http_requests": ota_requests,
            "evil_http_requests": ota_evil_requests,
            "evil_http_delta": ota_evil_http_delta,
            "attack_before_version": ota_before_version,
            "attack_after_version": ota_after_version,
            "control_before_version": ota_control_before_version,
            "control_after_version": ota_control_after_version,
            "control_http_delta": ota_control_http_delta,
            "attack_new_dut_excerpt": ota_attack_new_dut_text[-500:],
        },
        "dut": {
            "ota_applied": ota_applied,
            "ota_blocked": ota_blocked,
            "ota_signed_ok": ota_signed_ok,
            "state_version": state_version,
        },
    },
}

os.makedirs(RESULTS, exist_ok=True)
json_out = json.dumps(summary, indent=2, ensure_ascii=False)
with open(f"{RESULTS}/summary.json", "w", encoding="utf-8") as f:
    f.write(json_out)

report = f"""# IoT Security Testbed - Run Report

**Scenar:** `{scenario}`

## KPI

| Metrika | Hodnota | Interpretacia |
|---------|---------|---------------|
| P1 mqtt_unauth_denied  | {kpi['P1_mqtt_unauth_denied']} | Baseline=0 / Secure>0 |
| P2 coap_plain_gets     | {kpi['P2_coap_plain_gets']} | Baseline>0 / Secure=0 |
| P2 coap_plain_blocked  | {kpi['P2_coap_plain_blocked']} | Secure>0 |
| P2 coap_dtls_failures  | {kpi['P2_coap_dtls_failures']} | Secure>0 |
| P2 coap_dtls_ok        | {kpi['P2_coap_dtls_ok']} | Secure>=1 |
| P3 ota_evil_applied    | {kpi['P3_ota_evil_applied']} | Baseline>0 / Secure=0 |
| P3 ota_evil_blocked    | {kpi['P3_ota_evil_blocked']} | Secure>0 |
| P3 ota_signed_ok       | {kpi['P3_ota_signed_ok']} | Secure>=1 |

## Raw data

```json
{json_out}
```
"""

with open(f"{RESULTS}/report.md", "w", encoding="utf-8") as f:
    f.write(report)

print("collector: summary.json a report.md vytvorene")
print(f"KPI: {json.dumps(kpi, ensure_ascii=False)}")

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches

    scenario_kpi = {
        "mqtt-baseline": [
            ("P1_mqtt_unauth_success", "Uspesne utoky\n(ocakavane: 30)", lambda v: v >= 28),
            ("P1_mqtt_unauth_denied", "Odmietnutia\n(ocakavane: 0)", lambda v: v == 0),
        ],
        "mqtt-secure": [
            ("P1_mqtt_unauth_denied", "Odmietnutia\n(ocakavane: 30)", lambda v: v >= 28),
            ("P1_mqtt_unauth_success", "Uspesne utoky\n(ocakavane: 0)", lambda v: v == 0),
        ],
        "coap-baseline": [
            ("P2_coap_plain_gets", "Plaintext GETs\n(ocakavane: >0)", lambda v: v > 0),
        ],
        "coap-secure": [
            ("P2_coap_plain_blocked", "Port 5683 blokovany\n(ocakavane: >0)", lambda v: v > 0),
            ("P2_coap_dtls_failures", "DTLS zly PSK odmietnuty\n(ocakavane: >=1)", lambda v: v >= 1),
            ("P2_coap_dtls_ok", "DTLS spravny PSK OK\n(ocakavane: 1)", lambda v: v >= 1),
        ],
        "ota-baseline": [
            ("P3_ota_evil_applied", "Evil firmware aplikovany\n(ocakavane: 1)", lambda v: v > 0),
        ],
        "ota-secure": [
            ("P3_ota_signed_ok", "Podpisana aktualizacia OK\n(ocakavane: 1)", lambda v: v > 0),
            ("P3_ota_evil_blocked", "Evil firmware zablokovany\n(ocakavane: 1)", lambda v: v > 0),
            ("P3_ota_evil_applied", "Evil firmware aplikovany\n(ocakavane: 0)", lambda v: v == 0),
        ],
    }

    kpi_cfg = scenario_kpi.get(scenario, [])
    if kpi_cfg:
        labels = [label for _, label, _ in kpi_cfg]
        values = [kpi.get(key, 0) for key, _, _ in kpi_cfg]
        colors = ["#27AE60" if ok_fn(kpi.get(key, 0)) else "#E74C3C" for key, _, ok_fn in kpi_cfg]

        fig_h = max(3.0, len(labels) * 1.4 + 1.2)
        fig, ax = plt.subplots(figsize=(9, fig_h))
        bars = ax.barh(labels, values, color=colors, edgecolor="white", linewidth=1.5, height=0.55)

        xmax = max(values + [1]) * 1.45
        ax.set_xlim(0, xmax)
        for bar, value in zip(bars, values):
            ax.text(
                value + xmax * 0.02,
                bar.get_y() + bar.get_height() / 2,
                str(int(value)),
                va="center",
                ha="left",
                fontsize=12,
                fontweight="bold",
            )

        ax.set_xlabel("KPI hodnota", fontsize=11)
        ax.set_title(f"KPI vysledky - {scenario}", fontsize=13, fontweight="bold")
        ax.tick_params(axis="y", labelsize=10)

        ok_patch = mpatches.Patch(color="#27AE60", label="OK")
        fail_patch = mpatches.Patch(color="#E74C3C", label="FAIL")
        ax.legend(handles=[ok_patch, fail_patch], fontsize=9, loc="lower right")

        for spine in ["top", "right"]:
            ax.spines[spine].set_visible(False)
        ax.grid(True, axis="x", alpha=0.3, linestyle="--")

        plt.tight_layout()
        plt.savefig(f"{RESULTS}/fig_kpi.png", dpi=150, bbox_inches="tight", facecolor="white")
        plt.close()
        print(f"collector: fig_kpi.png ulozeny do {RESULTS}/")
except ImportError:
    pass
except Exception as e:
    print(f"collector: [WARN] Graf sa nepodarilo vygenerovat: {e}")

time.sleep(2)
