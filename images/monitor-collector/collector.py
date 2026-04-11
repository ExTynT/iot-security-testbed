"""Zber a sumarizácia artefaktov z jedného behu testbedu.

Modul číta logy, stavové súbory a PCAP artefakty z adresárovej štruktúry
jedného runu a vytvára z nich `summary.json`, `report.md` a voliteľný KPI graf.
Výstup je určený pre audit behov aj pre následnú agregovanú analýzu.
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone

LOGS = "/logs"
RESULTS = "/results"
STATE = "/state"
PCAP = "/pcap"
SCHEMA_VERSION = "1.0.0"

SCENARIO_COMPOSE_FILES = {
    "mqtt-baseline": ["docker-compose.yml"],
    "mqtt-secure": ["docker-compose.yml", "docker-compose.mqtt-secure.yml"],
    "coap-baseline": ["docker-compose.yml"],
    "coap-secure": ["docker-compose.yml", "docker-compose.coap-secure.yml"],
    "ota-baseline": ["docker-compose.yml"],
    "ota-secure": ["docker-compose.yml", "docker-compose.ota-secure.yml"],
}
RUN_ID_RE = re.compile(r"^\d{8}-\d{6}$")


def read(path, warn_missing=True):
    """Načíta textový súbor a pri chybe vráti prázdny reťazec.

    Parameters
    ----------
    path : str or os.PathLike
        Cesta k načítavanému súboru.
    warn_missing : bool, default=True
        Ak je `True`, pri chýbajúcom súbore vypíše warning na stderr.

    Returns
    -------
    str
        Obsah súboru alebo prázdny reťazec pri chybe.
    """
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
    """Načíta voliteľný textový súbor bez výpisu warningu."""
    return read(path, warn_missing=False)


def file_size(path):
    """Vráti veľkosť súboru v bajtoch alebo nulu pri chybe."""
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def read_state_version(state_dir=STATE):
    """Načíta verziu DUT zo stavového adresára.

    Preferuje novší formát `version.json`, ale zachováva kompatibilitu aj so
    starším `version.txt`.
    """
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


def utc_now_iso():
    """Vráti aktuálny UTC čas v stabilnom ISO 8601 formáte."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def infer_run_id_from_state_dir(state_dir):
    """Odvodí `run_id` z nadradeného adresára `state/`."""
    state_path = os.path.abspath(os.fspath(state_dir))
    run_id = os.path.basename(os.path.dirname(state_path))
    if RUN_ID_RE.match(run_id):
        return run_id
    return ""


def infer_created_at_from_run_id(run_id):
    """Prepočíta timestamp z `run_id` na ISO 8601 UTC čas."""
    if not RUN_ID_RE.match(run_id):
        return ""
    try:
        parsed = datetime.strptime(run_id, "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return ""
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def read_run_meta(state_dir=STATE):
    """Načíta provenienčné metadáta runu.

    Parameters
    ----------
    state_dir : str, default=STATE
        Cesta k adresáru `state/`.

    Returns
    -------
    dict
        Metadáta s kľúčmi `run_id`, `git_commit` a `created_at`. Ak
        `run_meta.json` neexistuje alebo je poškodený, vracajú sa inferované
        alebo bezpečné fallback hodnoty.
    """
    inferred_run_id = infer_run_id_from_state_dir(state_dir)
    inferred_created_at = infer_created_at_from_run_id(inferred_run_id)
    metadata = {
        "run_id": inferred_run_id or "unknown-run",
        "git_commit": "unknown",
        "created_at": inferred_created_at or utc_now_iso(),
    }
    raw = read_optional(f"{state_dir}/run_meta.json").strip()
    if not raw:
        return metadata

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return metadata

    run_id = str(parsed.get("run_id", "")).strip()
    git_commit = str(parsed.get("git_commit", "")).strip()
    created_at = str(parsed.get("created_at", "")).strip()
    if run_id:
        metadata["run_id"] = run_id
    if git_commit:
        metadata["git_commit"] = git_commit
    if created_at:
        metadata["created_at"] = created_at
    else:
        inferred_created_at = infer_created_at_from_run_id(metadata["run_id"])
        if inferred_created_at:
            metadata["created_at"] = inferred_created_at
    return metadata


def profile_for_scenario(scenario):
    """Preloží názov scenára na profil `baseline` alebo `secure`."""
    if scenario.endswith("-baseline"):
        return "baseline"
    if scenario.endswith("-secure"):
        return "secure"
    return "unknown"


def compose_files_for_scenario(scenario):
    """Vráti predvolený zoznam Compose súborov pre daný scenár."""
    compose_files = SCENARIO_COMPOSE_FILES.get(scenario)
    if compose_files:
        return compose_files
    return ["docker-compose.yml"]


def read_compose_files(state_dir=STATE):
    """Načíta použité Compose súbory z `state/compose_files.txt`.

    Ak súbor neexistuje, použije deterministicý fallback odvodený zo scenára.
    """
    compose_files = [
        line.strip()
        for line in read_optional(f"{state_dir}/compose_files.txt").splitlines()
        if line.strip()
    ]
    if compose_files:
        return compose_files

    scenario = read_optional(f"{state_dir}/scenario.txt").strip()
    return compose_files_for_scenario(scenario)


def parse_mqtt(scenario, mqtt_log="", attacks_log="", mqtt_control_log=""):
    """Vyhodnotí MQTT KPI a doplnkové warningy pre jeden beh.

    Parameters
    ----------
    scenario : str
        Názov scenára, napríklad `mqtt-baseline` alebo `mqtt-secure`.
    mqtt_log : str, default=""
        Obsah logu brokeru.
    attacks_log : str, default=""
        Obsah centrálneho logu útokov.
    mqtt_control_log : str, default=""
        Obsah logu kontrolného autorizovaného klienta.

    Returns
    -------
    dict
        Slovník so sekciami `kpi`, `warnings`, `evidence` a `raw`.
    """
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
    """Vyhodnotí CoAP a DTLS/PSK KPI pre jeden beh.

    Returns
    -------
    dict
        Slovník so sekciami `kpi`, `warnings`, `evidence` a `raw`.
    """
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
    """Vyhodnotí OTA artefakty a odvodí výsledok útoku alebo kontroly.

    Returns
    -------
    dict
        Slovník so sekciami `kpi`, `warnings`, `evidence`, `raw` a `dut`.
    """
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


def build_summary(
    scenario,
    logs=None,
    state_version="",
    pcap_bytes=None,
    run_metadata=None,
    compose_files=None,
):
    """Zostaví finálny `summary.json` pre jeden run.

    Parameters
    ----------
    scenario : str
        Názov vykonaného scenára.
    logs : dict, optional
        Mapovanie názvov logov na ich textový obsah.
    state_version : str, default=""
        Verzia DUT načítaná zo stavových súborov.
    pcap_bytes : dict, optional
        Veľkosti PCAP súborov v bajtoch.
    run_metadata : dict, optional
        Provenienčné metadáta runu.
    compose_files : list[str], optional
        Zoznam použitých Compose súborov.

    Returns
    -------
    dict
        Kompletný serializovateľný slovník pre `summary.json`.
    """
    logs = logs or {}
    pcap_bytes = pcap_bytes or {}
    run_metadata = run_metadata or {}
    compose_files = compose_files or compose_files_for_scenario(scenario)

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
        "meta": {
            "schema_version": SCHEMA_VERSION,
            "run_id": str(run_metadata.get("run_id", "unknown-run")),
            "profile": profile_for_scenario(scenario),
            "git_commit": str(run_metadata.get("git_commit", "unknown")),
            "created_at": str(run_metadata.get("created_at", utc_now_iso())),
            "compose_files": compose_files,
        },
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
    """Vytvorí Markdown report odvodený zo summary dát."""
    scenario = summary["scenario"]
    meta = summary["meta"]
    kpi = summary["kpi"]
    json_out = json.dumps(summary, indent=2, ensure_ascii=False)

    return f"""# IoT Security Testbed - Run Report

**Scenar:** `{scenario}`
**Run ID:** `{meta['run_id']}`
**Profil:** `{meta['profile']}`
**Git commit:** `{meta['git_commit']}`
**Vytvorene:** `{meta['created_at']}`

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
    """Vygeneruje KPI graf pre scenár, ak je dostupný matplotlib.

    Returns
    -------
    bool
        `True`, ak bol graf vytvorený, inak `False`.
    """
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
            ("P2_coap_plain_blocked", "Plaintext endpoint disabled\n(ocakavane: >0)", lambda value: value > 0),
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
    """Načíta všetky vstupy potrebné pre kolektor.

    Returns
    -------
    tuple
        Šestica `(scenario, logs, state_version, pcap_bytes, run_metadata,
        compose_files)`.
    """
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
    run_metadata = read_run_meta(state_dir)
    compose_files = read_compose_files(state_dir)
    pcap_bytes = {
        "mqtt": file_size(f"{pcap_dir}/mqtt.pcap"),
        "coap": file_size(f"{pcap_dir}/coap.pcap"),
        "ota": file_size(f"{pcap_dir}/ota.pcap"),
        "ota_evil": file_size(f"{pcap_dir}/ota_evil.pcap"),
    }
    return scenario, logs, state_version, pcap_bytes, run_metadata, compose_files


def write_outputs(summary, results_dir=RESULTS):
    """Zapíše `summary.json` a `report.md` do výsledkového adresára."""
    os.makedirs(results_dir, exist_ok=True)

    json_out = json.dumps(summary, indent=2, ensure_ascii=False)
    with open(f"{results_dir}/summary.json", "w", encoding="utf-8") as handle:
        handle.write(json_out)

    report = build_report(summary)
    with open(f"{results_dir}/report.md", "w", encoding="utf-8") as handle:
        handle.write(report)


def main():
    """Spustí zber artefaktov a vytvorí výsledné súbory kolektora."""
    scenario, logs, state_version, pcap_bytes, run_metadata, compose_files = load_collection_inputs()
    summary = build_summary(
        scenario=scenario,
        logs=logs,
        state_version=state_version,
        pcap_bytes=pcap_bytes,
        run_metadata=run_metadata,
        compose_files=compose_files,
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
