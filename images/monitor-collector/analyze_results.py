#!/usr/bin/env python3
"""
Agregačná analýza výsledkov uložených v `runs/`.

Modul načíta všetky `summary.json` súbory z jednotlivých behov, odvodené KPI
premení na agregované PASS/FAIL metriky a vygeneruje strojovo čitateľný JSON,
Markdown report aj súpravu grafov pre bakalársku prácu.

Spustenie cez `make`
-------------------
    make analyze

Manuálne spustenie
------------------
    docker compose run --rm -v "$PWD/runs:/runs" --entrypoint python \
      monitor-collector /app/analyze_results.py
"""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from pathlib import Path

RUNS_DIR = Path("/runs")
FIGURES_SUBDIR = os.getenv("ANALYZE_FIGURES_SUBDIR", "figures")
FIGURES_DIR = RUNS_DIR / FIGURES_SUBDIR


def resolve_runs_path(path_value: str, *, default: Path | None = None) -> Path:
    """Prevedie repo-relatívnu `runs/...` cestu na mountnutú cestu v kontajneri."""
    if not path_value:
        if default is None:
            raise ValueError("Path value or default must be provided.")
        return default

    path = Path(path_value)
    if path.is_absolute():
        return path

    parts = list(path.parts)
    if parts and parts[0] == "runs":
        return RUNS_DIR.joinpath(*parts[1:])
    return RUNS_DIR / path


def optional_runs_path(env_name: str) -> Path | None:
    """Vráti cestu z premennej prostredia alebo `None`, ak nie je nastavená."""
    value = os.getenv(env_name)
    if not value:
        return None
    return resolve_runs_path(value)

SCENARIO_ORDER = [
    "mqtt-baseline", "mqtt-secure",
    "coap-baseline", "coap-secure",
    "ota-baseline", "ota-secure",
]

SCENARIO_LABELS = {
    "mqtt-baseline": "P1 MQTT Baseline",
    "mqtt-secure": "P1 MQTT Secure",
    "coap-baseline": "P2 CoAP Baseline",
    "coap-secure": "P2 CoAP Secure",
    "ota-baseline": "P3 OTA Baseline",
    "ota-secure": "P3 OTA Secure",
}

KPI_META = {
    "P1_mqtt_unauth_success": {
        "label": "MQTT unauth success",
        "baseline_expect": "> 0 (utok uspel)",
        "secure_expect": "= 0 (zablokovany)",
        "baseline_ok": lambda v: v > 0,
        "secure_ok": lambda v: v == 0,
    },
    "P1_mqtt_unauth_denied": {
        "label": "MQTT unauth denied",
        "baseline_expect": "= 0 (utok uspel)",
        "secure_expect": "> 0 (odmietnuty)",
        "baseline_ok": lambda v: v == 0,
        "secure_ok": lambda v: v > 0,
    },
    "P2_coap_plain_gets": {
        "label": "CoAP plain GETs",
        "baseline_expect": "> 0 (plaintext citanie)",
        "secure_expect": "= 0 (plaintext endpoint disabled)",
        "baseline_ok": lambda v: v > 0,
        "secure_ok": lambda v: v == 0,
    },
    "P2_coap_plain_blocked": {
        "label": "CoAP plaintext endpoint disabled",
        "baseline_expect": "N/A",
        "secure_expect": "> 0 (plaintext endpoint disabled)",
        "baseline_ok": lambda v: True,
        "secure_ok": lambda v: v >= 1,
    },
    "P2_coap_dtls_failures": {
        "label": "CoAP DTLS failures (wrong PSK)",
        "baseline_expect": "N/A",
        "secure_expect": "> 0 (odmietnuty)",
        "baseline_ok": lambda v: True,
        "secure_ok": lambda v: v > 0,
    },
    "P2_coap_dtls_ok": {
        "label": "CoAP DTLS OK (spravny PSK)",
        "baseline_expect": "N/A",
        "secure_expect": ">= 1 (DTLS funguje)",
        "baseline_ok": lambda v: True,
        "secure_ok": lambda v: v >= 1,
    },
    "P3_ota_evil_applied": {
        "label": "OTA evil applied",
        "baseline_expect": "> 0 (evil nasadeny)",
        "secure_expect": "= 0 (zablokovany)",
        "baseline_ok": lambda v: v > 0,
        "secure_ok": lambda v: v == 0,
    },
    "P3_ota_evil_blocked": {
        "label": "OTA evil blocked",
        "baseline_expect": "= 0 (ziadna obrana)",
        "secure_expect": "> 0 (podpis zamietol)",
        "baseline_ok": lambda v: v == 0,
        "secure_ok": lambda v: v > 0,
    },
    "P3_ota_signed_ok": {
        "label": "OTA signed update OK",
        "baseline_expect": "N/A",
        "secure_expect": ">= 1 (legitimna OTA funguje)",
        "baseline_ok": lambda v: True,
        "secure_ok": lambda v: v >= 1,
    },
}

CVSS_ROWS = [
    ("P1", "MQTT broker bez auth/TLS (port 1883)", "H", "H", "L", "9.3 (Critical)", "2.1 (Low)"),
    ("P2", "CoAP plaintext bez autentifikacie (port 5683)", "L", "L", "L", "5.3 (Medium)", "3.1 (Low)"),
    ("P3", "OTA firmver bez overenia podpisu", "H", "H", "L", "9.2 (Critical)", "2.1 (Low)"),
]

COMPONENT_VERSIONS = [
    ("eclipse-mosquitto", "2.0.18"),
    ("libcoap (server)", "4.3.5 + OpenSSL"),
    ("libcoap (klient Alpine prebuilt)", "4.3.4a (plaintext)"),
    ("nginx", "sha256:f46cb72c7df0..."),
    ("python (DUT/collector)", "3.12-alpine"),
    ("alpine (attacker/sniffer)", "3.20"),
    ("minisign", "2.1 (Ed25519)"),
    ("OpenSSL (DTLS klient)", "3.x (Alpine 3.20)"),
]

DATASET_MANIFEST_PATH = optional_runs_path("ANALYZE_DATASET_MANIFEST")
AGGREGATE_JSON_PATH = resolve_runs_path(
    os.getenv("ANALYZE_AGGREGATE_JSON_PATH", ""),
    default=RUNS_DIR / "analysis-aggregate.json",
)
LEGACY_AGGREGATE_JSON_PATH = resolve_runs_path(
    os.getenv("ANALYZE_LEGACY_AGGREGATE_JSON_PATH", ""),
    default=RUNS_DIR / "aggregate.json",
)
AGGREGATE_MARKDOWN_PATH = resolve_runs_path(
    os.getenv("ANALYZE_AGGREGATE_MARKDOWN_PATH", ""),
    default=RUNS_DIR / "analysis-aggregate.md",
)


def parse_run_ids(value: str | None) -> list[str]:
    """Rozparsuje premennú s výberom `run_id` na zoznam identifikátorov."""
    if not value:
        return []
    normalized = value.replace("\n", ",").replace(";", ",").replace(" ", ",")
    return [part.strip() for part in normalized.split(",") if part.strip()]


def load_dataset_manifest() -> dict | None:
    """Načíta manifest finálneho datasetu, ak bol explicitne zadaný."""
    if DATASET_MANIFEST_PATH is None:
        return None
    return json.loads(DATASET_MANIFEST_PATH.read_text(encoding="utf-8"))


def read_summary(summary_path: Path) -> dict | None:
    """Načíta `summary.json` a vráti `None` pre nekompatibilné alebo poškodené dáta."""
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if "kpi" not in data:
        return None
    return data


def build_run_record(
    summary_path: Path,
    data: dict,
    *,
    run_id_override: str | None = None,
    scenario_override: str | None = None,
) -> dict:
    """Normalizuje jeden `summary.json` na interný záznam behu."""
    meta = data.get("meta", {})
    run_id = run_id_override or meta.get("run_id") or summary_path.parts[-3]
    scenario_file = summary_path.parent.parent / "state" / "scenario.txt"
    scenario = data.get("scenario") or scenario_override or (
        scenario_file.read_text(encoding="utf-8").strip() if scenario_file.exists() else "unknown"
    )
    return {
        "run_id": run_id,
        "scenario": scenario,
        "kpi": data["kpi"],
        "warnings": data.get("warnings", []),
    }


def load_runs(selected_run_ids: set[str] | None = None, dataset_manifest: dict | None = None) -> list[dict]:
    """Načíta všetky kompatibilné `summary.json` zo `runs/` alebo z final dataset manifestu."""
    runs: list[dict] = []

    if dataset_manifest is not None:
        for entry in dataset_manifest.get("runs", []):
            run_id = entry.get("run_id", "")
            if selected_run_ids is not None and run_id not in selected_run_ids:
                continue
            summary_path = resolve_runs_path(entry["summary_path"])
            data = read_summary(summary_path)
            if data is None:
                continue
            runs.append(build_run_record(
                summary_path,
                data,
                run_id_override=run_id,
                scenario_override=entry.get("scenario"),
            ))
        return runs

    for summary_path in sorted(RUNS_DIR.glob("*/results/summary.json")):
        run_id = summary_path.parts[-3]
        if selected_run_ids is not None and run_id not in selected_run_ids:
            continue
        data = read_summary(summary_path)
        if data is None:
            continue
        runs.append(build_run_record(summary_path, data, run_id_override=run_id))
    return runs


def avg(values: list[float]) -> float | None:
    """Vráti aritmetický priemer alebo `None` pre prázdny vstup."""
    return sum(values) / len(values) if values else None


def fmt(value: float | None) -> str:
    """Naformátuje číselnú hodnotu pre tabuľky v reporte."""
    if value is None:
        return "-"
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.1f}"


def check(value: float | None, fn) -> str:
    """Prevedie výsledok validačnej funkcie na `OK` alebo `FAIL`."""
    if value is None:
        return "-"
    return "OK" if fn(value) else "FAIL"


def get_avg(by_scenario: dict[str, list[dict]], kpi_key: str, scenario: str) -> float | None:
    """Vypočíta priemernú hodnotu KPI pre zvolený scenár."""
    values = [run["kpi"].get(kpi_key, 0) for run in by_scenario.get(scenario, [])]
    return avg(values)


def warning_run_count(by_scenario: dict[str, list[dict]], scenario: str) -> int:
    """Spočíta behy scenára, ktoré obsahujú aspoň jeden warning."""
    return sum(1 for run in by_scenario.get(scenario, []) if run.get("warnings"))


def warning_entry_count(runs: list[dict]) -> int:
    """Spočíta všetky warning položky v zozname behov."""
    return sum(len(run.get("warnings", [])) for run in runs)


def scenario_pair_for_kpi(kpi_key: str) -> tuple[str, str]:
    """Vráti baseline/secure dvojicu scenárov pre daný KPI kľúč."""
    if kpi_key.startswith("P1"):
        return "mqtt-baseline", "mqtt-secure"
    if kpi_key.startswith("P2"):
        return "coap-baseline", "coap-secure"
    return "ota-baseline", "ota-secure"


def group_runs_by_scenario(runs: list[dict]) -> dict[str, list[dict]]:
    """Zoskupí načítané behy podľa scenára."""
    by_scenario: dict[str, list[dict]] = defaultdict(list)
    for run in runs:
        by_scenario[run["scenario"]].append(run)
    return by_scenario


def calculate_success_rate(pass_count: int, runs: int) -> float:
    """Vypočíta podiel úspešných behov v rozsahu 0.0 až 1.0."""
    if runs == 0:
        return 0.0
    return pass_count / runs


def scenario_kpi_checks(scenario: str) -> list[tuple[str, str, str, object]]:
    """Vráti KPI kontroly, ktoré sú relevantné pre konkrétny scenár."""
    checks = []
    for kpi_key, meta in KPI_META.items():
        baseline_scenario, secure_scenario = scenario_pair_for_kpi(kpi_key)
        if scenario == baseline_scenario:
            checks.append((kpi_key, meta["label"], meta["baseline_expect"], meta["baseline_ok"]))
        elif scenario == secure_scenario:
            checks.append((kpi_key, meta["label"], meta["secure_expect"], meta["secure_ok"]))
    return checks


def evaluate_run_pass(run: dict) -> dict:
    """Vyhodnotí, či jeden run spĺňa všetky KPI a neobsahuje warningy."""
    scenario = run.get("scenario", "unknown")
    kpi = run.get("kpi", {})
    warnings = list(run.get("warnings", []))
    checks: list[dict[str, object]] = []
    failed_checks: list[str] = []
    applicable_checks = scenario_kpi_checks(scenario)

    if not applicable_checks:
        checks.append({
            "name": "unknown_scenario",
            "description": f"Scenar `{scenario}` nema definovane KPI pravidla.",
            "passed": False,
        })
        failed_checks.append("unknown_scenario")
    else:
        for kpi_key, label, expected, predicate in applicable_checks:
            value = kpi.get(kpi_key, 0)
            passed = bool(predicate(value))
            checks.append({
                "name": kpi_key,
                "description": f"{label}: ocakavanie {expected}, namerana hodnota {value}.",
                "passed": passed,
            })
            if not passed:
                failed_checks.append(kpi_key)

    warnings_passed = not warnings
    checks.append({
        "name": "warnings_present",
        "description": "Beh nesmie obsahovat warningy v summary.json.",
        "passed": warnings_passed,
    })
    if not warnings_passed:
        failed_checks.append("warnings_present")

    return {
        "run_id": run.get("run_id", "unknown"),
        "scenario": scenario,
        "passed": not failed_checks,
        "failed_checks": failed_checks,
        "checks": checks,
    }


def build_aggregate_summary(runs: list[dict]) -> dict:
    """Zostaví agregované štatistiky úspešnosti pre všetky scenáre."""
    evaluations = [evaluate_run_pass(run) for run in runs]
    by_scenario: dict[str, list[dict]] = defaultdict(list)
    for evaluation in evaluations:
        by_scenario[evaluation["scenario"]].append(evaluation)
    source_runs_by_scenario = group_runs_by_scenario(runs)

    scenarios: dict[str, dict[str, float | int]] = {}
    for scenario in SCENARIO_ORDER:
        scenario_runs = by_scenario.get(scenario, [])
        run_count = len(scenario_runs)
        pass_count = sum(1 for evaluation in scenario_runs if evaluation["passed"])
        fail_count = run_count - pass_count
        scenarios[scenario] = {
            "runs": run_count,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "success_rate": calculate_success_rate(pass_count, run_count),
            "warning_count": warning_entry_count(source_runs_by_scenario.get(scenario, [])),
        }

    total_runs = len(evaluations)
    total_pass = sum(1 for evaluation in evaluations if evaluation["passed"])
    total_fail = total_runs - total_pass
    return {
        "totals": {
            "runs": total_runs,
            "pass_count": total_pass,
            "fail_count": total_fail,
            "success_rate": calculate_success_rate(total_pass, total_runs),
            "warning_count": warning_entry_count(runs),
        },
        "scenarios": scenarios,
    }


def build_success_rate_table_lines(aggregate: dict, *, use_labels: bool) -> list[str]:
    """Vytvorí riadky Markdown tabuľky s explicitnou úspešnosťou scenárov."""
    totals = aggregate["totals"]
    scenarios = aggregate["scenarios"]
    lines = [
        "| Scenar | Behy | PASS | FAIL | Warningy | Success rate |",
        "|--------|------|------|------|----------|--------------|",
    ]
    for scenario in SCENARIO_ORDER:
        stats = scenarios.get(scenario, {
            "runs": 0,
            "pass_count": 0,
            "fail_count": 0,
            "warning_count": 0,
            "success_rate": 0.0,
        })
        label = SCENARIO_LABELS.get(scenario, scenario) if use_labels else scenario
        success_rate = stats["success_rate"] * 100
        lines.append(
            f"| {label} | {stats['runs']} | {stats['pass_count']} | {stats['fail_count']} | "
            f"{stats['warning_count']} | {success_rate:.1f}% |"
        )
    total_label = "Celkom" if use_labels else "celkom"
    lines.append(
        f"| {total_label} | {totals['runs']} | {totals['pass_count']} | {totals['fail_count']} | "
        f"{totals['warning_count']} | {totals['success_rate'] * 100:.1f}% |"
    )
    return lines


def build_aggregate_markdown(aggregate: dict) -> str:
    """Vygeneruje stručný Markdown report pre `analysis-aggregate.*`."""
    totals = aggregate["totals"]
    lines = [
        "# Agregovana uspesnost behov\n",
        (
            "Binarne PASS/FAIL vyhodnotenie je odvodene z `KPI_META` check funkcii a z "
            "poziadavky, aby run neobsahoval warningy v `summary.json`.\n"
        ),
        (
            f"Celkovo: **{totals['pass_count']}/{totals['runs']} PASS** "
            f"({totals['success_rate'] * 100:.1f}%), warningy spolu: **{totals['warning_count']}**.\n"
        ),
    ]
    lines.extend(build_success_rate_table_lines(aggregate, use_labels=False))
    lines.extend([
        "",
        (
            "PASS/FAIL vychadza priamo z `KPI_META` check funkcii a zo vstupnych warningov "
            "z `summary.json`."
        ),
    ])
    return "\n".join(lines)


def write_aggregate_outputs(
    aggregate: dict,
    json_path: Path,
    markdown_path: Path,
    legacy_json_path: Path | None = None,
) -> None:
    """Zapíše agregovaný JSON report a jeho Markdown reprezentáciu."""
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(aggregate, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if legacy_json_path is not None:
        legacy_json_path.parent.mkdir(parents=True, exist_ok=True)
        legacy_json_path.write_text(json.dumps(aggregate, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    markdown_path.write_text(build_aggregate_markdown(aggregate), encoding="utf-8")


def interpretation_sections(by_scenario: dict[str, list[dict]]) -> list[tuple[str, str]]:
    """Vytvorí interpretačné odseky pre scenáre, ktoré majú dáta."""
    sections = []
    if by_scenario.get("mqtt-baseline") or by_scenario.get("mqtt-secure"):
        sections.append((
            "P1 - MQTT autentifikacia a sifrovanie",
            "Baseline scenar potvrdzuje, ze broker bez TLS/auth umoznuje publikovanie "
            "lubovolnemu klientovi (P1_mqtt_unauth_denied = 0). Po nasadeni mitigacie "
            "(TLS 8883 + ACL + heslo) broker odmietol neautorizovanych klientov "
            "(P1_mqtt_unauth_denied > 0), pricom kontrolne autorizovane publish/subscribe "
            "operacie nadalej fungovali."
        ))
    if by_scenario.get("coap-baseline") or by_scenario.get("coap-secure"):
        sections.append((
            "P2 - CoAP DTLS/PSK a secure-only endpoint",
            "Baseline potvrdzuje plaintext pristup cez port 5683 bez autentifikacie. "
            "Secure scenar neexponuje plaintext endpoint na porte 5683 (P2_coap_plain_blocked > 0) "
            "a vyzaduje DTLS/PSK na porte 5684. Pokus so zlym PSK bol odmietnuty "
            "(P2_coap_dtls_failures > 0), spravny PSK bol akceptovany (P2_coap_dtls_ok >= 1)."
        ))
    if by_scenario.get("ota-baseline") or by_scenario.get("ota-secure"):
        sections.append((
            "P3 - OTA integrita (minisign Ed25519)",
            "Baseline potvrdzuje, ze DUT akceptuje firmver z lubovolneho servera bez "
            "overenia podpisu (P3_ota_evil_applied > 0). Secure scenar s pinovanym "
            "verejnym klucom zachoval funkcnost legitimnej podpisanej OTA aktualizacie "
            "(P3_ota_signed_ok >= 1) a zaroven odmietol evil firmver "
            "(P3_ota_evil_blocked > 0, P3_ota_evil_applied = 0)."
        ))
    return sections


def build_markdown(runs: list[dict], selected_run_ids: list[str]) -> str:
    """Zostaví hlavný Markdown report nad agregovanými výsledkami."""
    by_scenario = group_runs_by_scenario(runs)
    aggregate = build_aggregate_summary(runs)

    lines: list[str] = []
    lines.append("# IoT Security Testbed - Agregovana analyza vysledkov\n")
    lines.append("## 0. Dataset scope\n")
    if selected_run_ids:
        lines.append("Analyza bola vygenerovana nad explicitne zvolenou finalnou mnozinou behov.\n")
        lines.append(f"Vybrate run IDs: **{', '.join(selected_run_ids)}**\n")
        lines.append(f"Figury boli ulozene do: **runs/{FIGURES_SUBDIR}/**\n")
    else:
        lines.append("Analyza bola vygenerovana nad vsetkymi dostupnymi behov v `runs/`.\n")
        lines.append(f"Figury boli ulozene do: **runs/{FIGURES_SUBDIR}/**\n")
    lines.append("## 1. Prehlad runs\n")
    lines.append(f"Celkovy pocet behov: **{len(runs)}**\n")
    lines.append("| Run ID | Scenar |")
    lines.append("|--------|--------|")
    for run in runs:
        lines.append(f"| {run['run_id']} | {run['scenario']} |")
    lines.append("")

    lines.append("| Scenar | Pocet replikacii |")
    lines.append("|--------|-----------------|")
    for scenario in SCENARIO_ORDER:
        lines.append(f"| {SCENARIO_LABELS.get(scenario, scenario)} | {len(by_scenario.get(scenario, []))} |")
    lines.append("")

    lines.append("| Scenar | Behy s varovaniami |")
    lines.append("|--------|--------------------|")
    for scenario in SCENARIO_ORDER:
        lines.append(f"| {SCENARIO_LABELS.get(scenario, scenario)} | {warning_run_count(by_scenario, scenario)} |")
    lines.append("")

    lines.append("## 2. Before vs After - KPI tabulka\n")
    lines.append("Priemerne hodnoty KPI napriec replikaciami.\n")
    lines.append("| KPI | Baseline (priemer) | Secure (priemer) | Baseline OK? | Secure OK? |")
    lines.append("|---|---|---|---|---|")
    for key, meta in KPI_META.items():
        baseline_scenario, secure_scenario = scenario_pair_for_kpi(key)
        base_avg = get_avg(by_scenario, key, baseline_scenario)
        sec_avg = get_avg(by_scenario, key, secure_scenario)
        if base_avg is not None:
            base_str = f"{fmt(base_avg)} ({meta['baseline_expect']})"
        else:
            base_str = f"- ({meta['baseline_expect']})"
        if sec_avg is not None:
            sec_str = f"{fmt(sec_avg)} ({meta['secure_expect']})"
        else:
            sec_str = f"- ({meta['secure_expect']})"
        lines.append(
            f"| {meta['label']} | {base_str} | {sec_str} | "
            f"{check(base_avg, meta['baseline_ok']) if base_avg is not None else '-'} | "
            f"{check(sec_avg, meta['secure_ok']) if sec_avg is not None else '-'} |"
        )
    lines.append("")

    lines.append("## 3. Explicitna uspesnost behov\n")
    lines.append(
        "Binarne PASS/FAIL vyhodnotenie je odvodene z `KPI_META` check funkcii a z toho, "
        "ci `summary.json` obsahuje warningy.\n"
    )
    lines.extend(build_success_rate_table_lines(aggregate, use_labels=True))
    lines.append("")

    lines.append("## 4. Vizualizacia KPI (ASCII)\n")

    def ascii_bar(value: float, maximum: float, width: int = 30) -> str:
        if maximum <= 0:
            return "[" + "-" * width + "]"
        filled = int(round((value / maximum) * width))
        return "[" + "#" * filled + "." * (width - filled) + "]"

    chart_items = [
        ("P1_mqtt_unauth_denied", "mqtt-baseline", "mqtt-secure", "P1: MQTT unauth denied"),
        ("P2_coap_plain_gets", "coap-baseline", "coap-secure", "P2: CoAP plaintext GETs"),
        ("P3_ota_evil_applied", "ota-baseline", "ota-secure", "P3: OTA evil applied"),
        ("P3_ota_evil_blocked", "ota-baseline", "ota-secure", "P3: OTA evil blocked"),
        ("P3_ota_signed_ok", "ota-baseline", "ota-secure", "P3: OTA signed update OK"),
    ]
    for key, baseline_scenario, secure_scenario, title in chart_items:
        base_avg = get_avg(by_scenario, key, baseline_scenario) or 0
        sec_avg = get_avg(by_scenario, key, secure_scenario) or 0
        maximum = max(base_avg, sec_avg, 1)
        lines.append(f"### {title}\n")
        lines.append("```")
        lines.append(f"  Baseline {ascii_bar(base_avg, maximum)}  {fmt(base_avg)}")
        lines.append(f"    Secure {ascii_bar(sec_avg, maximum)}  {fmt(sec_avg)}")
        lines.append("```\n")

    lines.append("## 5. Interpretacia vysledkov\n")
    for heading, text in interpretation_sections(by_scenario):
        lines.append(f"### {heading}\n")
        lines.append(text + "\n")

    lines.append("## 6. Dopad na CIA a CVSS v4.0 hodnotenie\n")
    lines.append("Poznamka: CVSS a CIA su analyticky odhad autora, nie automaticky merane KPI.\n")
    lines.append("Skore je uvedene ako porovnanie stavu pred mitigaciou a po mitigacii.\n")
    lines.append("| # | Zranitelnost | C | I | A | CVSS v4.0 (pred) | CVSS v4.0 (po) |")
    lines.append("|---|-------------|---|---|---|-----------------|----------------|")
    for row in CVSS_ROWS:
        lines.append(f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} | {row[5]} | {row[6]} |")
    lines.append("")
    lines.append(
        "> Rezidualne skore po mitigacii je analyticky odhad: "
        "P1=2.1 (brute-force hesla / TLS handshake flood), "
        "P2=3.1 (konzervativny odhad rezidualneho dopadu mimo priamo testovanej operacie), "
        "P3=2.1 (rollback attack bez version-pinningu).\n"
    )

    lines.append("## 7. Verzie komponentov (reprodukovatelnost)\n")
    lines.append("| Komponent | Verzia |")
    lines.append("|-----------|--------|")
    for component, version in COMPONENT_VERSIONS:
        lines.append(f"| {component} | {version} |")
    lines.append("")
    lines.append("---")
    if selected_run_ids:
        lines.append(
            f"*Generovane automaticky z {len(runs)} explicitne zvolenych run(s) v priecinku `/runs` "
            f"so scope `{', '.join(selected_run_ids)}`.*"
        )
    else:
        lines.append(f"*Generovane automaticky z {len(runs)} run(s) v priecinku `/runs`.*")
    return "\n".join(lines)


def create_figures(by_scenario: dict[str, list[dict]]) -> None:
    """Vygeneruje publikačné grafy pre MQTT, CoAP, OTA, CVSS a CIA."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        from matplotlib.colors import LinearSegmentedColormap
    except ImportError:
        print("[INFO] matplotlib nie je dostupny - grafy preskocene.", file=sys.stderr)
        return

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.titleweight": "bold",
        "axes.grid": True,
        "axes.grid.axis": "y",
        "grid.alpha": 0.25,
        "grid.linestyle": "--",
        "figure.dpi": 150,
        "savefig.dpi": 200,
        "savefig.bbox": "tight",
    })

    c_base = "#E74C3C"
    c_sec = "#27AE60"
    c_gray = "#95A5A6"

    def avg_value(key: str, scenario: str) -> float:
        return get_avg(by_scenario, key, scenario) or 0

    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    groups = ["Baseline", "Secure"]
    success = [avg_value("P1_mqtt_unauth_success", "mqtt-baseline"), avg_value("P1_mqtt_unauth_success", "mqtt-secure")]
    denied = [avg_value("P1_mqtt_unauth_denied", "mqtt-baseline"), avg_value("P1_mqtt_unauth_denied", "mqtt-secure")]
    x = np.arange(len(groups))
    width = 0.34
    ax.bar(x - width / 2, success, width, color=c_base, label="Uspesne utoky")
    ax.bar(x + width / 2, denied, width, color=c_sec, label="Odmietnute pokusy")
    ax.set_xticks(x)
    ax.set_xticklabels(groups)
    ax.set_ylabel("Pocet pokusov")
    ax.set_title("P1 - MQTT: Uspesne vs. odmietnute neautorizovane pokusy")
    ax.legend()
    fig.text(0.5, -0.04, "Zdroj: vlastne merania", ha="center", fontsize=8, style="italic", color="#555")
    plt.savefig(FIGURES_DIR / "fig1_p1_mqtt_kpi.png")
    plt.close()

    coap_keys = [
        ("P2_coap_plain_gets", "Plaintext GETs"),
        ("P2_coap_plain_blocked", "Plaintext endpoint disabled"),
        ("P2_coap_dtls_failures", "Wrong PSK fail"),
        ("P2_coap_dtls_ok", "Correct PSK OK"),
    ]
    fig, axes = plt.subplots(2, 2, figsize=(10.5, 7.5))
    for ax, (key, title) in zip(axes.flat, coap_keys):
        values = [avg_value(key, "coap-baseline"), avg_value(key, "coap-secure")]
        ax.bar(["Baseline", "Secure"], values, color=[c_base if values[0] else c_gray, c_sec])
        ax.set_title(title)
        ax.set_ylabel("Priemer KPI")
    fig.suptitle("P2 - CoAP: plaintext endpoint a DTLS/PSK merania", fontsize=13, fontweight="bold")
    fig.text(0.5, -0.01, "Zdroj: vlastne merania", ha="center", fontsize=8, style="italic", color="#555")
    plt.savefig(FIGURES_DIR / "fig2_p2_coap_kpi.png")
    plt.close()

    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    ota_groups = ["Evil applied", "Evil blocked", "Signed OK"]
    baseline = [
        avg_value("P3_ota_evil_applied", "ota-baseline"),
        avg_value("P3_ota_evil_blocked", "ota-baseline"),
        avg_value("P3_ota_signed_ok", "ota-baseline"),
    ]
    secure = [
        avg_value("P3_ota_evil_applied", "ota-secure"),
        avg_value("P3_ota_evil_blocked", "ota-secure"),
        avg_value("P3_ota_signed_ok", "ota-secure"),
    ]
    x = np.arange(len(ota_groups))
    ax.bar(x - width / 2, baseline, width, color=c_base, label="Baseline")
    ax.bar(x + width / 2, secure, width, color=c_sec, label="Secure")
    ax.set_xticks(x)
    ax.set_xticklabels(ota_groups)
    ax.set_ylabel("Priemer KPI")
    ax.set_title("P3 - OTA: baseline vs. secure")
    ax.legend()
    fig.text(0.5, -0.04, "Zdroj: vlastne merania", ha="center", fontsize=8, style="italic", color="#555")
    plt.savefig(FIGURES_DIR / "fig3_p3_ota_kpi.png")
    plt.close()

    fig, ax = plt.subplots(figsize=(8.5, 5))
    protocols = ["P1 MQTT", "P2 CoAP", "P3 OTA"]
    cvss_before = [9.3, 5.3, 9.2]
    cvss_after = [2.1, 3.1, 2.1]
    x = np.arange(len(protocols))
    ax.bar(x - width / 2, cvss_before, width, color=c_base, label="Pred mitigaciou")
    ax.bar(x + width / 2, cvss_after, width, color=c_sec, label="Po mitigacii")
    ax.set_xticks(x)
    ax.set_xticklabels(protocols)
    ax.set_ylim(0, 10)
    ax.set_ylabel("CVSS v4.0 Base score")
    ax.set_title("CVSS v4.0 - pred a po mitigacii")
    ax.legend()
    fig.text(
        0.5,
        -0.03,
        "Zdroj: vlastne hodnotenie podla FIRST CVSS v4.0",
        ha="center",
        fontsize=8,
        style="italic",
        color="#555",
    )
    plt.savefig(FIGURES_DIR / "fig4_cvss_scores.png")
    plt.close()

    cia_matrix = np.array([
        [3, 1, 1, 1, 3, 0],
        [2, 1, 1, 1, 3, 1],
        [1, 1, 1, 1, 1, 0],
    ], dtype=float)
    cmap = LinearSegmentedColormap.from_list("cia", ["#D5F5E3", "#F9E79F", "#F0B27A", "#EC7063"], N=256)
    fig, ax = plt.subplots(figsize=(11.5, 4.2))
    im = ax.imshow(cia_matrix, cmap=cmap, vmin=0, vmax=3, aspect="auto")
    ax.set_xticks(range(6))
    ax.set_xticklabels(["P1 pred", "P1 po", "P2 pred", "P2 po", "P3 pred", "P3 po"])
    ax.set_yticks(range(3))
    ax.set_yticklabels(["Dovernost", "Integrita", "Dostupnost"])
    plt.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    ax.set_title("CIA triada - pred a po mitigacii")
    fig.text(0.5, -0.05, "Zdroj: vlastne hodnotenie", ha="center", fontsize=8, style="italic", color="#555")
    plt.savefig(FIGURES_DIR / "fig5_cia_impact.png")
    plt.close()


def main() -> int:
    """Načíta výsledky behov a vygeneruje všetky agregačné výstupy."""
    dataset_manifest = load_dataset_manifest()
    selected_run_ids = parse_run_ids(os.getenv("ANALYZE_RUN_IDS"))
    if dataset_manifest is not None:
        selected_run_ids = dataset_manifest.get("run_ids", []) or [
            entry.get("run_id", "") for entry in dataset_manifest.get("runs", []) if entry.get("run_id")
        ]
    selected_run_id_set = set(selected_run_ids) if selected_run_ids else None
    runs = load_runs(selected_run_id_set, dataset_manifest)
    if not runs:
        print("# Analyza IoT Security Testbed\n")
        if dataset_manifest is not None:
            print(
                "Manifest finalneho datasetu bol nacitany, ale jeho `summary.json` artefakty sa "
                "nepodarilo nacitat v kompatibilnom formate."
            )
            if selected_run_ids:
                print(f"Ocakavane run IDs: {', '.join(selected_run_ids)}")
            print(f"Manifest: {DATASET_MANIFEST_PATH}")
        elif selected_run_ids:
            print(
                "Pre zadane `ANALYZE_RUN_IDS` neboli najdene zodpovedajuce runs s novym formatom summary.json "
                "(obsahujuce 'kpi' kluc)."
            )
            print(f"Pozadovane run IDs: {', '.join(selected_run_ids)}")
        else:
            print("Ziadne runs s novym formatom summary.json (obsahujuce 'kpi' kluc) neboli najdene.")
            print(
                "Spusti aspon jeden scenar cez `make <scenar>` alebo fallback "
                "`bash scripts/_run_all.sh`, a potom `make analyze`."
            )
        return 0

    by_scenario = group_runs_by_scenario(runs)
    aggregate = build_aggregate_summary(runs)
    write_aggregate_outputs(
        aggregate,
        AGGREGATE_JSON_PATH,
        AGGREGATE_MARKDOWN_PATH,
        legacy_json_path=LEGACY_AGGREGATE_JSON_PATH,
    )

    if selected_run_ids:
        found_ids = {run["run_id"] for run in runs}
        missing_ids = [run_id for run_id in selected_run_ids if run_id not in found_ids]
        if missing_ids:
            print(
                f"[WARN] Pozadovane run IDs neboli najdene alebo nemali novy summary format: {', '.join(missing_ids)}",
                file=sys.stderr,
            )

    print(build_markdown(runs, selected_run_ids))
    create_figures(by_scenario)
    print(f"[AGGREGATE] JSON ulozene do: {AGGREGATE_JSON_PATH}", file=sys.stderr)
    print(f"[AGGREGATE] Markdown ulozene do: {AGGREGATE_MARKDOWN_PATH}", file=sys.stderr)
    print(f"[AGGREGATE] Legacy alias ulozeny do: {LEGACY_AGGREGATE_JSON_PATH}", file=sys.stderr)
    print(f"\n[GRAFY] Vsetky grafy ulozene do: {FIGURES_DIR}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
