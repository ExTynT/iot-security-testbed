import json
import os
import re
import sys
import time

LOGS = "/logs"
RESULTS = "/results"
STATE = "/state"
PCAP = "/pcap"


def read(path, warn_missing=True):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read()
    except FileNotFoundError:
        if warn_missing:
            print(f"[WARN] Chybajuci subor: {path}", file=sys.stderr, flush=True)
        return ""
    except Exception as exc:
        print(f"[WARN] Chyba citania {path}: {exc}", file=sys.stderr, flush=True)
        return ""


def read_optional(path):
    return read(path, warn_missing=False)


def file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def read_state_version(state_dir=STATE):
    version_json = read_optional(f"{state_dir}/version.json").strip()
    if version_json:
        try:
            state = json.loads(version_json)
            version = str(state.get("version", "")).strip()
            if version:
                return version
        except json.JSONDecodeError:
            pass
    return read_optional(f"{state_dir}/version.txt").strip()


def parse_mqtt(scenario, mqtt_log="", attacks_log="", mqtt_control_log=""):
    warnings = []
    if scenario == "mqtt-secure" and not mqtt_control_log:
        warnings.append("mqtt_control_log_missing")
    if scenario == "mqtt-secure" and mqtt_control_log and not re.search(r"AUTH_WRITE_OK", mqtt_control_log, re.I):
        warnings.append("mqtt_auth_write_not_confirmed")
    if scenario == "mqtt-secure" and mqtt_control_log and not re.search(r"AUTH_READ_OK", mqtt_control_log, re.I):
        warnings.append("mqtt_auth_read_not_confirmed")

    mqtt_published = len(re.findall(r"PUBLISH", mqtt_log, re.I))
    mqtt_unauth_success_log = len(re.findall(r"Received PUBLISH .*'cmd/ota'", mqtt_log, re.I))
    mqtt_unauth_success_marker = len(re.findall(r"P1_mqtt_unauth_success", attacks_log))
    mqtt_denied_connack = len(re.findall(r"Sending CONNACK .* \(0, 5\)", mqtt_log, re.I))
    mqtt_denied_marker = len(re.findall(r"P1_mqtt_unauth_denied", attacks_log))
    mqtt_auth_write_ok = len(re.findall(r"Received PUBLISH .*'cmd/test'", mqtt_log, re.I))
    mqtt_auth_read_ok = len(re.findall(r"AUTH_READ_OK", mqtt_control_log, re.I))

    if scenario.startswith("mqtt-"):
        mqtt_unauth_success = mqtt_unauth_success_marker or mqtt_unauth_success_log
        mqtt_denied = mqtt_denied_marker or mqtt_denied_connack
    else:
        mqtt_unauth_success = 0
        mqtt_denied = 0

    return {
        "kpi": {
            "P1_mqtt_unauth_denied": mqtt_denied,
            "P1_mqtt_unauth_success": mqtt_unauth_success,
        },
        "warnings": warnings,
        "evidence": {
            "P1_mqtt_unauth_success": (
                "attacks.log marker" if mqtt_unauth_success_marker else "mqtt.log cmd/ota publish"
            ),
            "P1_mqtt_unauth_denied": "attacks.log marker" if mqtt_denied_marker else "mqtt.log CONNACK(0,5)",
        },
        "raw": {
            "unauth_success": mqtt_unauth_success,
            "denied": mqtt_denied,
            "published": mqtt_published,
            "auth_write_ok": mqtt_auth_write_ok,
            "auth_read_ok": mqtt_auth_read_ok,
        },
    }


def parse_coap(
    scenario,
    coap_log="",
    attacks_log="",
    coap_plain_probe_log="",
    coap_baseline_probe_log="",
    coap_dtls_wrong_psk_log="",
    coap_dtls_ok_log="",
):
    warnings = []
    if scenario == "coap-secure" and not coap_plain_probe_log:
        warnings.append("coap_plain_probe_log_missing")
    if scenario == "coap-secure" and not coap_dtls_wrong_psk_log:
        warnings.append("coap_dtls_wrong_psk_log_missing")
    if scenario == "coap-secure" and not coap_dtls_ok_log:
        warnings.append("coap_dtls_ok_log_missing")

    coap_plain_accessible = len(re.findall(r"^ACCESSIBLE\b", coap_plain_probe_log, re.M))
    coap_baseline_accessible = len(re.findall(r"^ACCESSIBLE\b", coap_baseline_probe_log, re.M))
    coap_plain_blocked_log = len(re.findall(r"^BLOCKED\b", coap_plain_probe_log, re.M))
    coap_plain_received_server = len(re.findall(r"v:1 t:CON", coap_log, re.I))
    if scenario == "coap-secure":
        coap_plain_received = coap_plain_accessible
    else:
        coap_plain_received = (
            coap_baseline_accessible
            or coap_plain_received_server
            or len(re.findall(r"P2_coap_plain_gets", attacks_log))
        )

    coap_dtls_failures = len(re.findall(r"^FAIL\b", coap_dtls_wrong_psk_log, re.M)) or len(
        re.findall(r"P2_coap_dtls_failure", attacks_log)
    )
    coap_plain_blocked = coap_plain_blocked_log or len(re.findall(r"P2_coap_plain_blocked", attacks_log))
    coap_plain_accessible_marked = len(re.findall(r"P2_coap_plain_accessible", attacks_log))
    if not coap_plain_accessible:
        coap_plain_accessible = coap_plain_accessible_marked
    coap_dtls_ok = len(re.findall(r"CoAP response 2\.05", coap_dtls_ok_log, re.I)) or len(
        re.findall(r"P2_coap_dtls_ok", attacks_log)
    )

    return {
        "kpi": {
            "P2_coap_plain_gets": coap_plain_received,
            "P2_coap_plain_blocked": coap_plain_blocked,
            "P2_coap_dtls_failures": coap_dtls_failures,
            "P2_coap_dtls_ok": coap_dtls_ok,
        },
        "warnings": warnings,
        "evidence": {
            "P2_coap_plain_gets": "coap_baseline_probe.log or coap.log",
            "P2_coap_plain_blocked": "coap_plain_probe.log",
            "P2_coap_dtls_failures": "coap_dtls_wrong_psk.log",
            "P2_coap_dtls_ok": "coap_dtls_ok.log",
        },
        "raw": {
            "plain_gets_received": coap_plain_received,
            "plain_blocked": coap_plain_blocked,
            "plain_accessible": coap_plain_accessible,
            "baseline_accessible": coap_baseline_accessible,
            "plain_gets_server_log": coap_plain_received_server,
            "dtls_failures": coap_dtls_failures,
            "dtls_ok": coap_dtls_ok,
        },
    }


def parse_ota(
    scenario,
    ota_access_log="",
    ota_evil_access_log="",
    ota_control_log="",
    ota_attack_log="",
):
    warnings = []
    if scenario in {"ota-baseline", "ota-secure"} and not ota_access_log:
        warnings.append("ota_access_log_missing")
    if scenario in {"ota-baseline", "ota-secure"} and not ota_evil_access_log:
        warnings.append("ota_evil_access_log_missing")
    if scenario == "ota-secure" and not ota_control_log:
        warnings.append("ota_control_log_missing")
    if scenario in {"ota-baseline", "ota-secure"} and not ota_attack_log:
        warnings.append("ota_attack_log_missing")

    ota_requests = len(re.findall(r"GET /", ota_access_log))
    ota_evil_requests = len(re.findall(r"GET /", ota_evil_access_log))
    ota_control_signed_ok = len(re.findall(r"^SIGNED_OK\b", ota_control_log, re.M))
    ota_control_before = re.search(r"^BEFORE_VERSION=(.+)$", ota_control_log, re.M)
    ota_control_after = re.search(r"^AFTER_VERSION=(.+)$", ota_control_log, re.M)
    ota_control_http_before = re.search(r"^OFFICIAL_HTTP_BEFORE=(\d+)$", ota_control_log, re.M)
    ota_control_http_after = re.search(r"^OFFICIAL_HTTP_AFTER=(\d+)$", ota_control_log, re.M)
    ota_control_before_version = ota_control_before.group(1).strip() if ota_control_before else ""
    ota_control_after_version = ota_control_after.group(1).strip() if ota_control_after else ""
    if ota_control_http_before and ota_control_http_after:
        ota_control_http_delta = max(
            int(ota_control_http_after.group(1)) - int(ota_control_http_before.group(1)),
            0,
        )
    else:
        ota_control_http_delta = 0

    ota_attack_before = re.search(r"^BEFORE_VERSION=(.+)$", ota_attack_log, re.M)
    ota_attack_after = re.search(r"^AFTER_VERSION=(.+)$", ota_attack_log, re.M)
    ota_attack_http_before = re.search(r"^EVIL_HTTP_BEFORE=(\d+)$", ota_attack_log, re.M)
    ota_attack_http_after = re.search(r"^EVIL_HTTP_AFTER=(\d+)$", ota_attack_log, re.M)
    ota_before_version = ota_attack_before.group(1).strip() if ota_attack_before else ""
    ota_after_version = ota_attack_after.group(1).strip() if ota_attack_after else ""
    if ota_attack_http_before and ota_attack_http_after:
        ota_evil_http_delta = max(
            int(ota_attack_http_after.group(1)) - int(ota_attack_http_before.group(1)),
            0,
        )
    else:
        ota_evil_http_delta = 0

    ota_attack_new_dut = re.search(r"DUT_NEW_BEGIN\s*(.*?)\s*DUT_NEW_END", ota_attack_log, re.S)
    ota_attack_new_dut_text = ota_attack_new_dut.group(1) if ota_attack_new_dut else ""

    ota_applied = 1 if (
        ota_before_version
        and ota_after_version
        and ota_before_version != ota_after_version
        and ota_evil_http_delta > 0
    ) else 0
    ota_blocked = 1 if (
        ota_evil_http_delta > 0
        and re.search(
            r"ZAMIETNUT|NEPLATN|SIGNATURE_INVALID|MANIFEST_INVALID|HASH_MISMATCH|ROLLBACK_BLOCKED",
            ota_attack_new_dut_text,
            re.I,
        )
    ) else 0
    ota_signed_ok = 1 if (
        ota_control_signed_ok
        and ota_control_before_version
        and ota_control_after_version
        and ota_control_before_version != ota_control_after_version
        and ota_control_http_delta > 0
    ) else 0

    return {
        "kpi": {
            "P3_ota_evil_applied": ota_applied,
            "P3_ota_evil_blocked": ota_blocked,
            "P3_ota_signed_ok": ota_signed_ok,
        },
        "warnings": warnings,
        "evidence": {
            "P3_ota_evil_applied": "ota_attack.log before/after version + ota_evil access delta",
            "P3_ota_evil_blocked": "ota_attack.log new DUT lines + ota_evil access delta",
            "P3_ota_signed_ok": "ota_control.log signed_ok + official access delta",
        },
        "raw": {
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
        },
    }


def build_summary(scenario, logs=None, state_version="", pcap_bytes=None):
    logs = logs or {}
    pcap_bytes = pcap_bytes or {}

    mqtt_result = parse_mqtt(
        scenario=scenario,
        mqtt_log=logs.get("mqtt.log", ""),
        attacks_log=logs.get("attacks.log", ""),
        mqtt_control_log=logs.get("mqtt_control.log", ""),
    )
    coap_result = parse_coap(
        scenario=scenario,
        coap_log=logs.get("coap.log", ""),
        attacks_log=logs.get("attacks.log", ""),
        coap_plain_probe_log=logs.get("coap_plain_probe.log", ""),
        coap_baseline_probe_log=logs.get("coap_baseline_probe.log", ""),
        coap_dtls_wrong_psk_log=logs.get("coap_dtls_wrong_psk.log", ""),
        coap_dtls_ok_log=logs.get("coap_dtls_ok.log", ""),
    )
    ota_result = parse_ota(
        scenario=scenario,
        ota_access_log=logs.get("ota_access.log", ""),
        ota_evil_access_log=logs.get("ota_evil_access.log", ""),
        ota_control_log=logs.get("ota_control.log", ""),
        ota_attack_log=logs.get("ota_attack.log", ""),
    )

    kpi = {
        **mqtt_result["kpi"],
        **coap_result["kpi"],
        **ota_result["kpi"],
    }

    return {
        "scenario": scenario,
        "kpi": kpi,
        "warnings": mqtt_result["warnings"] + coap_result["warnings"] + ota_result["warnings"],
        "evidence": {
            **mqtt_result["evidence"],
            **coap_result["evidence"],
            **ota_result["evidence"],
        },
        "artifacts": {
            "pcap_bytes": {
                "mqtt": pcap_bytes.get("mqtt", 0),
                "coap": pcap_bytes.get("coap", 0),
                "ota": pcap_bytes.get("ota", 0),
                "ota_evil": pcap_bytes.get("ota_evil", 0),
            },
            "logs_present": {
                "mqtt_log": bool(logs.get("mqtt.log", "")),
                "coap_log": bool(logs.get("coap.log", "")),
                "dut_log": bool(logs.get("dut.log", "")),
                "ota_access_log": bool(logs.get("ota_access.log", "")),
                "ota_evil_access_log": bool(logs.get("ota_evil_access.log", "")),
            },
        },
        "raw": {
            "mqtt": mqtt_result["raw"],
            "coap": coap_result["raw"],
            "ota": ota_result["raw"],
            "dut": {
                **ota_result["dut"],
                "state_version": state_version,
            },
        },
    }


def build_report(summary):
    scenario = summary["scenario"]
    kpi = summary["kpi"]
    json_out = json.dumps(summary, indent=2, ensure_ascii=False)

    return f"""# IoT Security Testbed - Run Report

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


def render_figure(summary, results_dir=RESULTS):
    scenario = summary["scenario"]
    kpi = summary["kpi"]

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.patches as mpatches
    import matplotlib.pyplot as plt

    scenario_kpi = {
        "mqtt-baseline": [
            ("P1_mqtt_unauth_success", "Uspesne utoky\n(ocakavane: 30)", lambda value: value >= 28),
            ("P1_mqtt_unauth_denied", "Odmietnutia\n(ocakavane: 0)", lambda value: value == 0),
        ],
        "mqtt-secure": [
            ("P1_mqtt_unauth_denied", "Odmietnutia\n(ocakavane: 30)", lambda value: value >= 28),
            ("P1_mqtt_unauth_success", "Uspesne utoky\n(ocakavane: 0)", lambda value: value == 0),
        ],
        "coap-baseline": [
            ("P2_coap_plain_gets", "Plaintext GETs\n(ocakavane: >0)", lambda value: value > 0),
        ],
        "coap-secure": [
            ("P2_coap_plain_blocked", "Port 5683 blokovany\n(ocakavane: >0)", lambda value: value > 0),
            ("P2_coap_dtls_failures", "DTLS zly PSK odmietnuty\n(ocakavane: >=1)", lambda value: value >= 1),
            ("P2_coap_dtls_ok", "DTLS spravny PSK OK\n(ocakavane: 1)", lambda value: value >= 1),
        ],
        "ota-baseline": [
            ("P3_ota_evil_applied", "Evil firmware aplikovany\n(ocakavane: 1)", lambda value: value > 0),
        ],
        "ota-secure": [
            ("P3_ota_signed_ok", "Podpisana aktualizacia OK\n(ocakavane: 1)", lambda value: value > 0),
            ("P3_ota_evil_blocked", "Evil firmware zablokovany\n(ocakavane: 1)", lambda value: value > 0),
            ("P3_ota_evil_applied", "Evil firmware aplikovany\n(ocakavane: 0)", lambda value: value == 0),
        ],
    }

    kpi_cfg = scenario_kpi.get(scenario, [])
    if not kpi_cfg:
        return False

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
    plt.savefig(f"{results_dir}/fig_kpi.png", dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
    return True


def load_collection_inputs(logs_dir=LOGS, state_dir=STATE, pcap_dir=PCAP):
    scenario = read(f"{state_dir}/scenario.txt").strip() or "unknown"
    logs = {
        "mqtt.log": read_optional(f"{logs_dir}/mqtt.log"),
        "coap.log": read_optional(f"{logs_dir}/coap.log"),
        "dut.log": read_optional(f"{logs_dir}/dut.log"),
        "ota_access.log": read_optional(f"{logs_dir}/ota_access.log"),
        "ota_evil_access.log": read_optional(f"{logs_dir}/ota_evil_access.log"),
        "attacks.log": read_optional(f"{logs_dir}/attacks.log"),
        "mqtt_control.log": read_optional(f"{logs_dir}/mqtt_control.log"),
        "coap_plain_probe.log": read_optional(f"{logs_dir}/coap_plain_probe.log"),
        "coap_baseline_probe.log": read_optional(f"{logs_dir}/coap_baseline_probe.log"),
        "coap_dtls_wrong_psk.log": read_optional(f"{logs_dir}/coap_dtls_wrong_psk.log"),
        "coap_dtls_ok.log": read_optional(f"{logs_dir}/coap_dtls_ok.log"),
        "ota_control.log": read_optional(f"{logs_dir}/ota_control.log"),
        "ota_attack.log": read_optional(f"{logs_dir}/ota_attack.log"),
    }
    state_version = read_state_version(state_dir)
    pcap_bytes = {
        "mqtt": file_size(f"{pcap_dir}/mqtt.pcap"),
        "coap": file_size(f"{pcap_dir}/coap.pcap"),
        "ota": file_size(f"{pcap_dir}/ota.pcap"),
        "ota_evil": file_size(f"{pcap_dir}/ota_evil.pcap"),
    }
    return scenario, logs, state_version, pcap_bytes


def write_outputs(summary, results_dir=RESULTS):
    os.makedirs(results_dir, exist_ok=True)

    json_out = json.dumps(summary, indent=2, ensure_ascii=False)
    with open(f"{results_dir}/summary.json", "w", encoding="utf-8") as handle:
        handle.write(json_out)

    report = build_report(summary)
    with open(f"{results_dir}/report.md", "w", encoding="utf-8") as handle:
        handle.write(report)


def main():
    scenario, logs, state_version, pcap_bytes = load_collection_inputs()
    summary = build_summary(
        scenario=scenario,
        logs=logs,
        state_version=state_version,
        pcap_bytes=pcap_bytes,
    )

    write_outputs(summary)

    print("collector: summary.json a report.md vytvorene")
    print(f"KPI: {json.dumps(summary['kpi'], ensure_ascii=False)}")

    try:
        if render_figure(summary):
            print(f"collector: fig_kpi.png ulozeny do {RESULTS}/")
    except ImportError:
        pass
    except Exception as exc:
        print(f"collector: [WARN] Graf sa nepodarilo vygenerovat: {exc}")

    time.sleep(2)


if __name__ == "__main__":
    main()
