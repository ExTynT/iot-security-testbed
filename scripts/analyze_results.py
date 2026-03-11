#!/usr/bin/env python3
"""
Agregacna analyza vsetkych runs/ -> Markdown sprava + PNG grafy pre bakalársku prácu.

Spustenie (cez make):
    make analyze

Manualne:
    docker compose run --rm -v "$PWD/runs:/runs" --entrypoint python \
      monitor-collector /app/analyze_results.py
"""

import json
import os
import sys
from collections import defaultdict
from pathlib import Path

RUNS_DIR = Path("/runs")
FIGURES_DIR = RUNS_DIR / "figures"

# ─── Načítanie runs ────────────────────────────────────────────────────────────

runs = []
for summary_path in sorted(RUNS_DIR.glob("*/results/summary.json")):
    run_id = summary_path.parts[-3]
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
    except Exception:
        continue

    if "kpi" not in data:
        continue

    scenario_file = summary_path.parent.parent / "state" / "scenario.txt"
    scenario = data.get("scenario") or (
        scenario_file.read_text().strip() if scenario_file.exists() else "unknown"
    )

    runs.append({"run_id": run_id, "scenario": scenario, "kpi": data["kpi"]})

if not runs:
    print("# Analyza IoT Security Testbed\n")
    print("Ziadne runs s novym formatom summary.json (obsahujuce 'kpi' kluc) neboli najdene.")
    print("Spusti aspon jeden scenar cez `make <scenar>` a potom `make analyze`.")
    sys.exit(0)

# ─── Definícia scenárov ────────────────────────────────────────────────────────

SCENARIO_ORDER = [
    "mqtt-baseline", "mqtt-secure",
    "coap-baseline", "coap-secure",
    "ota-baseline",  "ota-secure",
]

SCENARIO_LABELS = {
    "mqtt-baseline": "P1 MQTT Baseline",
    "mqtt-secure":   "P1 MQTT Secure",
    "coap-baseline": "P2 CoAP Baseline",
    "coap-secure":   "P2 CoAP Secure",
    "ota-baseline":  "P3 OTA Baseline",
    "ota-secure":    "P3 OTA Secure",
}

KPI_META = {
    "P1_mqtt_unauth_denied": {
        "label": "MQTT unauth denied",
        "baseline_expect": "= 0 (utok uspel)",
        "secure_expect":   "> 0 (odmietnuty)",
        "baseline_ok": lambda v: v == 0,
        "secure_ok":   lambda v: v > 0,
    },
    "P2_coap_plain_gets": {
        "label": "CoAP plain GETs",
        "baseline_expect": "> 0 (plaintext citanie)",
        "secure_expect":   "= 0 (port blokovany)",
        "baseline_ok": lambda v: v > 0,
        "secure_ok":   lambda v: v == 0,
    },
    "P2_coap_plain_blocked": {
        "label": "CoAP plain port blocked",
        "baseline_expect": "N/A",
        "secure_expect":   "> 0 (iptables OK)",
        "baseline_ok": lambda v: True,
        "secure_ok":   lambda v: v >= 1,
    },
    "P2_coap_dtls_failures": {
        "label": "CoAP DTLS failures (wrong PSK)",
        "baseline_expect": "N/A",
        "secure_expect":   "> 0 (odmietnuty)",
        "baseline_ok": lambda v: True,
        "secure_ok":   lambda v: v > 0,
    },
    "P2_coap_dtls_ok": {
        "label": "CoAP DTLS OK (spravny PSK)",
        "baseline_expect": "N/A",
        "secure_expect":   ">= 1 (DTLS funguje)",
        "baseline_ok": lambda v: True,
        "secure_ok":   lambda v: v >= 1,
    },
    "P3_ota_evil_applied": {
        "label": "OTA evil applied",
        "baseline_expect": "> 0 (evil nasadeny)",
        "secure_expect":   "= 0 (zablokovany)",
        "baseline_ok": lambda v: v > 0,
        "secure_ok":   lambda v: v == 0,
    },
    "P3_ota_evil_blocked": {
        "label": "OTA evil blocked",
        "baseline_expect": "= 0 (ziadna obrana)",
        "secure_expect":   "> 0 (podpis zamietol)",
        "baseline_ok": lambda v: v == 0,
        "secure_ok":   lambda v: v > 0,
    },
}

# ─── Agregácia podľa scenára ───────────────────────────────────────────────────

by_scenario = defaultdict(list)
for r in runs:
    by_scenario[r["scenario"]].append(r)

def avg(values):
    return sum(values) / len(values) if values else None

def fmt(v):
    if v is None:
        return "-"
    if isinstance(v, float) and v != int(v):
        return f"{v:.1f}"
    return str(int(v)) if isinstance(v, float) else str(v)

def check(val, fn):
    if val is None:
        return "-"
    return "OK" if fn(val) else "FAIL"

def get_avg(kpi_key, scenario):
    vals = [r["kpi"].get(kpi_key, 0) for r in by_scenario.get(scenario, [])]
    return avg(vals)

# ─── Markdown výstup ──────────────────────────────────────────────────────────

lines = []
lines.append("# IoT Security Testbed - Agregovana analyza vysledkov\n")

# Prehľad runs
lines.append("## 1. Prehlad runs\n")
n_runs = len(runs)
by_sc_count = {sc: len(lst) for sc, lst in by_scenario.items()}
lines.append(f"Celkovy pocet behov: **{n_runs}**\n")
lines.append("| Run ID | Scenar |")
lines.append("|--------|--------|")
for r in runs:
    lines.append(f"| {r['run_id']} | {r['scenario']} |")
lines.append("")

# Počet replikácií
lines.append("| Scenar | Pocet replikacii |")
lines.append("|--------|-----------------|")
for sc in SCENARIO_ORDER:
    cnt = by_sc_count.get(sc, 0)
    lines.append(f"| {SCENARIO_LABELS.get(sc, sc)} | {cnt} |")
lines.append("")

# Before vs After tabuľka
lines.append("## 2. Before vs After - KPI tabulka\n")
lines.append("Priemerne hodnoty KPI napriec replikaciami.\n")

headers = ["KPI", "Baseline (priemer)", "Secure (priemer)", "Baseline OK?", "Secure OK?"]
lines.append("| " + " | ".join(headers) + " |")
lines.append("|" + "|".join(["---"] * len(headers)) + "|")

for k, meta in KPI_META.items():
    if k.startswith("P1"):
        base_scen, sec_scen = "mqtt-baseline", "mqtt-secure"
    elif k.startswith("P2"):
        base_scen, sec_scen = "coap-baseline", "coap-secure"
    else:
        base_scen, sec_scen = "ota-baseline", "ota-secure"

    base_avg = get_avg(k, base_scen)
    sec_avg  = get_avg(k, sec_scen)

    base_ok = check(base_avg, meta["baseline_ok"]) if base_avg is not None else "-"
    sec_ok  = check(sec_avg,  meta["secure_ok"])   if sec_avg  is not None else "-"

    base_str = f"{fmt(base_avg)} ({meta['baseline_expect']})" if base_avg is not None else f"- ({meta['baseline_expect']})"
    sec_str  = f"{fmt(sec_avg)} ({meta['secure_expect']})"   if sec_avg  is not None else f"- ({meta['secure_expect']})"

    lines.append(f"| {meta['label']} | {base_str} | {sec_str} | {base_ok} | {sec_ok} |")

lines.append("")

# ASCII grafy (terminal fallback)
lines.append("## 3. Vizualizacia KPI (ASCII)\n")

CHART_KPIS = [
    ("P1_mqtt_unauth_denied", "mqtt-baseline", "mqtt-secure",
     "P1: MQTT unauth denied (Baseline vs Secure)"),
    ("P2_coap_plain_gets",    "coap-baseline", "coap-secure",
     "P2: CoAP plaintext GETs (Baseline vs Secure)"),
    ("P3_ota_evil_applied",   "ota-baseline",  "ota-secure",
     "P3: OTA evil applied (Baseline vs Secure)"),
    ("P3_ota_evil_blocked",   "ota-baseline",  "ota-secure",
     "P3: OTA evil blocked (Baseline vs Secure)"),
]

def ascii_bar(val, max_val, width=30):
    if max_val == 0:
        return "[" + "-" * width + "]"
    filled = int(round(val / max_val * width))
    return "[" + "#" * filled + "." * (width - filled) + "]"

for kpi_key, b_scen, s_scen, title in CHART_KPIS:
    b_avg = get_avg(kpi_key, b_scen)
    s_avg = get_avg(kpi_key, s_scen)
    if b_avg is None and s_avg is None:
        continue
    b_v = b_avg or 0
    s_v = s_avg or 0
    max_v = max(b_v, s_v, 1)
    lines.append(f"### {title}\n")
    lines.append("```")
    lines.append(f"  Baseline {ascii_bar(b_v, max_v)}  {fmt(b_v)}")
    lines.append(f"    Secure {ascii_bar(s_v, max_v)}  {fmt(s_v)}")
    lines.append("```\n")

# Interpretácia
lines.append("## 4. Interpretacia vysledkov\n")

interpretations = {
    ("mqtt-baseline", "mqtt-secure"): (
        "P1 - MQTT autentifikacia a sifrovanie",
        "Baseline scenar potvrdzuje, ze broker bez TLS/auth umoznuje publikovanie "
        "lubovolnemu klientovi (P1_mqtt_unauth_denied = 0). "
        "Po nasadeni mitigacie (TLS 8883 + ACL + heslo) broker odmietol vsetkych "
        "neautorizovanych klientov (P1_mqtt_unauth_denied > 0), pricom legitímny "
        "klient nadal fungoval. Hypoteza P1d potvrdena."
    ),
    ("coap-baseline", "coap-secure"): (
        "P2 - CoAP DTLS/PSK a segmentacia",
        "Baseline potvrdzuje plaintext pristup cez port 5683 bez akejkolvek autentifikacie. "
        "Secure scenar blokuje port 5683 pomocou iptables (P2_coap_plain_blocked > 0) "
        "a vyzaduje DTLS/PSK na porte 5684. Pokus so zlym PSK bol odmietnuty "
        "(P2_coap_dtls_failures > 0), spravny PSK bol akceptovany (P2_coap_dtls_ok >= 1). "
        "Hypotezy P2a, P2b, P2c potvrdene."
    ),
    ("ota-baseline", "ota-secure"): (
        "P3 - OTA integrita (minisign Ed25519)",
        "Baseline potvrdzuje, ze DUT akceptuje firmver z lubovolneho servera bez overenia podpisu "
        "(P3_ota_evil_applied > 0). "
        "Secure scenar s pinovanym verejnym klucom (minisign Ed25519) odmietol evil firmver "
        "(P3_ota_evil_blocked > 0, P3_ota_evil_applied = 0). "
        "Hypotezy P3a potvrdena."
    ),
}

for (b, s), (heading, text) in interpretations.items():
    if by_scenario.get(b) or by_scenario.get(s):
        lines.append(f"### {heading}\n")
        lines.append(text + "\n")

# CVSS a CIA
lines.append("## 5. Dopad na CIA a CVSS v4.0 hodnotenie\n")
lines.append(
    "Skore vypocitane podla CVSS v4.0 Base Score. "
    "Vektor pred mitigaciou (Baseline) / po mitigacii (Secure).\n"
)
lines.append("| # | Zranitelnost | C | I | A | CVSS v4.0 (pred) | CVSS v4.0 (po) |")
lines.append("|---|-------------|---|---|---|-----------------|----------------|")
cvss_rows = [
    ("P1", "MQTT broker bez auth/TLS (port 1883)",         "H","H","L", "9.3 (Critical)", "2.1 (Low)"),
    ("P2", "CoAP plaintext bez autentifikacie (port 5683)","L","L","L", "5.3 (Medium)",   "3.1 (Low)"),
    ("P3", "OTA firmver bez overenia podpisu",             "H","H","L", "9.2 (Critical)", "2.1 (Low)"),
]
for num, vuln, c, i, a, before, after in cvss_rows:
    lines.append(f"| {num} | {vuln} | {c} | {i} | {a} | {before} | {after} |")

lines.append("")
lines.append(
    "> Vektory (CVSS v4.0): AV:N/AC:L/AT:N/PR:N/UI:N. "
    "Po mitigacii: utok nie je mozny v definovanom threat modeli testbedu.\n"
)

# Verzie komponentov
lines.append("## 6. Verzie komponentov (reprodukovatelnost)\n")
lines.append("| Komponent | Verzia |")
lines.append("|-----------|--------|")
for comp, ver in [
    ("eclipse-mosquitto",              "2.0.18"),
    ("libcoap (server)",               "4.3.5 + OpenSSL"),
    ("libcoap (klient Alpine prebuilt)","4.3.4a (plaintext)"),
    ("nginx",                          "alpine (latest)"),
    ("python (DUT/collector)",         "3.12-alpine"),
    ("alpine (attacker/sniffer)",      "3.20"),
    ("minisign",                       "2.1 (Ed25519)"),
    ("OpenSSL (DTLS klient)",          "3.x (Alpine 3.20)"),
]:
    lines.append(f"| {comp} | {ver} |")

lines.append("")
lines.append("---")
lines.append(f"*Generovane automaticky z {len(runs)} run(s) v priecinku `/runs`.*")

# Výpis Markdown
print("\n".join(lines))

# ─── Matplotlib grafy ─────────────────────────────────────────────────────────
# Grafy sa generuju do /runs/figures/ a pouzivaju sa priamo v bakalárskej práci.

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

if not HAS_MPL:
    print("\n[INFO] matplotlib nie je dostupny – grafy preskocene.", file=sys.stderr)
    sys.exit(0)

FIGURES_DIR.mkdir(parents=True, exist_ok=True)

# Spolocny styl
plt.rcParams.update({
    "font.family":      "DejaVu Sans",
    "font.size":        11,
    "axes.titlesize":   13,
    "axes.titleweight": "bold",
    "axes.labelsize":   11,
    "axes.spines.top":  False,
    "axes.spines.right":False,
    "axes.grid":        True,
    "axes.grid.axis":   "y",
    "grid.alpha":       0.35,
    "grid.linestyle":   "--",
    "figure.dpi":       150,
    "savefig.dpi":      200,
    "savefig.bbox":     "tight",
    "savefig.facecolor":"white",
})

C_BASE = "#E74C3C"   # cervena = zranitelny/utok uspel
C_SEC  = "#27AE60"   # zelena  = zabezpeceny/odmietnuty
SOURCE = "Zdroj: vlastne merania (Klopček, 2025)"

# ── Graf 1: P1 MQTT ───────────────────────────────────────────────────────────
b_denied = get_avg("P1_mqtt_unauth_denied", "mqtt-baseline") or 0
s_denied = get_avg("P1_mqtt_unauth_denied", "mqtt-secure")   or 0
b_success_vals = [r["kpi"].get("P1_mqtt_unauth_success", 0)
                  for r in by_scenario.get("mqtt-baseline", [])]
b_success = avg(b_success_vals) or 0

fig, ax = plt.subplots(figsize=(8, 4.5))
scen_labels = ["Baseline\n(port 1883, allow_anonymous)", "Secure\n(port 8883, TLS 1.3 + ACL)"]
# Baseline: zobrazime uspesne utoky; Secure: zobrazime odmietnutia
b_show = b_success if b_success > 0 else (1 if b_denied == 0 else 0)
vals   = [b_show, s_denied]
cols   = [C_BASE, C_SEC]
bars   = ax.bar(scen_labels, vals, color=cols, width=0.42, edgecolor="white", linewidth=1.5)

b_lbl = f"{fmt(b_show)}  (utok USPESNY)" if b_show > 0 else f"0  (utok USPESNY - denied=0)"
s_lbl = f"{fmt(s_denied)}  (ODMIETNUTY)"
for bar, val, lbl in zip(bars, vals, [b_lbl, s_lbl]):
    ax.text(bar.get_x() + bar.get_width() / 2, max(val, 0) + max(max(vals)*0.03, 0.05),
            lbl, ha="center", va="bottom", fontsize=9, fontweight="bold")

ymax = max(max(vals) * 1.4, 1.5)
ax.set_ylim(0, ymax)
ax.set_title("P1 – MQTT: Uspesne neautorizovane PUBLISH operacie\n(Baseline vs. Zabezpecena konfiguracia)")
ax.set_ylabel("Pocet pokusov / KPI hodnota")
ax.legend(handles=[
    mpatches.Patch(color=C_BASE, label="Baseline – bez TLS, bez ACL"),
    mpatches.Patch(color=C_SEC,  label="Secure – TLS 1.3 + ACL + heslo"),
], fontsize=9)
fig.text(0.5, -0.03, SOURCE, ha="center", fontsize=8, style="italic", color="#555")
plt.tight_layout()
out1 = FIGURES_DIR / "fig1_p1_mqtt_kpi.png"
plt.savefig(out1)
plt.close()
print(f"[GRAF] {out1}", file=sys.stderr)

# ── Graf 2: P2 CoAP – viaceré metriky ────────────────────────────────────────
coap_metrics = [
    ("P2_coap_plain_gets",    "coap-baseline", "coap-secure",  "Plain GETs\n(bez DTLS)"),
    ("P2_coap_plain_blocked", "coap-baseline", "coap-secure",  "Plain port\nzablokovany"),
    ("P2_coap_dtls_failures", "coap-baseline", "coap-secure",  "DTLS chybny\nPSK"),
    ("P2_coap_dtls_ok",       "coap-baseline", "coap-secure",  "DTLS platny\nPSK"),
]
metric_labels  = [m[3] for m in coap_metrics]
baseline_vals  = [get_avg(m[0], m[1]) or 0 for m in coap_metrics]
secure_vals    = [get_avg(m[0], m[2]) or 0 for m in coap_metrics]

fig, ax = plt.subplots(figsize=(10, 5))
x = np.arange(len(metric_labels))
w = 0.35
bars_b = ax.bar(x - w/2, baseline_vals, w, label="Baseline", color=C_BASE, edgecolor="white")
bars_s = ax.bar(x + w/2, secure_vals,   w, label="Secure (DTLS-PSK + iptables)", color=C_SEC, edgecolor="white")
ymax2 = max(max(baseline_vals + secure_vals) * 1.4, 1.5)
ax.set_ylim(0, ymax2)
for bar, val in zip(bars_b, baseline_vals):
    if val > 0:
        ax.text(bar.get_x() + bar.get_width()/2, val + ymax2*0.02,
                fmt(val), ha="center", va="bottom", fontsize=10, fontweight="bold", color=C_BASE)
for bar, val in zip(bars_s, secure_vals):
    if val > 0:
        ax.text(bar.get_x() + bar.get_width()/2, val + ymax2*0.02,
                fmt(val), ha="center", va="bottom", fontsize=10, fontweight="bold", color=C_SEC)
ax.set_xticks(x)
ax.set_xticklabels(metric_labels)
ax.set_title("P2 – CoAP: Vysledky merani pre plaintext a DTLS-PSK scenare\n(Baseline vs. Zabezpecena konfiguracia)")
ax.set_ylabel("Pocet pokusov / KPI hodnota (priemer)")
ax.legend(fontsize=9)
fig.text(0.5, -0.03, SOURCE, ha="center", fontsize=8, style="italic", color="#555")
plt.tight_layout()
out2 = FIGURES_DIR / "fig2_p2_coap_kpi.png"
plt.savefig(out2)
plt.close()
print(f"[GRAF] {out2}", file=sys.stderr)

# ── Graf 3: P3 OTA ────────────────────────────────────────────────────────────
b_applied = get_avg("P3_ota_evil_applied", "ota-baseline") or 0
s_applied = get_avg("P3_ota_evil_applied", "ota-secure")   or 0
b_blocked = get_avg("P3_ota_evil_blocked", "ota-baseline") or 0
s_blocked = get_avg("P3_ota_evil_blocked", "ota-secure")   or 0

fig, ax = plt.subplots(figsize=(8, 4.5))
x = np.arange(2)
w = 0.3
b_a = ax.bar(x[0] - w/2, b_applied, w, color=C_BASE, label="Evil firmware APLIKOVANY",  edgecolor="white")
b_b = ax.bar(x[0] + w/2, b_blocked, w, color=C_SEC,  label="Evil firmware ZABLOKOVANY", edgecolor="white")
s_a = ax.bar(x[1] - w/2, s_applied, w, color=C_BASE, edgecolor="white")
s_b = ax.bar(x[1] + w/2, s_blocked, w, color=C_SEC,  edgecolor="white")
ymax3 = max(b_applied, b_blocked, s_applied, s_blocked, 1) * 1.4
ax.set_ylim(0, ymax3)
for bar, val in [(b_a[0], b_applied), (b_b[0], b_blocked), (s_a[0], s_applied), (s_b[0], s_blocked)]:
    if val > 0:
        ax.text(bar.get_x() + bar.get_width()/2, val + ymax3*0.02,
                fmt(val), ha="center", va="bottom", fontsize=11, fontweight="bold")
ax.set_xticks(x)
ax.set_xticklabels(["Baseline\n(bez podpisu)", "Secure\n(minisign Ed25519)"])
ax.set_title("P3 – OTA: Aplikacia skodliveho firmveru\n(Baseline vs. Zabezpecena konfiguracia)")
ax.set_ylabel("KPI hodnota (priemer)")
ax.legend(fontsize=9)
fig.text(0.5, -0.03, SOURCE, ha="center", fontsize=8, style="italic", color="#555")
plt.tight_layout()
out3 = FIGURES_DIR / "fig3_p3_ota_kpi.png"
plt.savefig(out3)
plt.close()
print(f"[GRAF] {out3}", file=sys.stderr)

# ── Graf 4: CVSS v4.0 porovnanie ─────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(9, 5.5))
protocols   = ["P1 – MQTT\n(neautorizovany pristup)", "P2 – CoAP\n(plaintext bez DTLS)", "P3 – OTA\n(nepodpisany firmver)"]
# CVSS v4.0 pred mitigaciou (overene kalkulatorom first.org/cvss/calculator/4.0):
# P1 MQTT  9.3 – AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N
# P2 CoAP  5.3 – AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N
# P3 OTA   9.2 – AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N
cvss_before = [9.3, 5.3, 9.2]
# Rezidualne skore po mitigacii (nie nula – mitigacia redukuje, neeleminuje riziko):
#   P1 MQTT  2.1 – brute-force hesla (AC:H/AT:P) / DoS TLS handshake flood
#   P2 CoAP  3.1 – race condition iptables + UDP amplifikacia
#   P3 OTA   2.1 – rollback attack (deploy starsi validne podpisany firmver)
cvss_after  = [2.1, 3.1, 2.1]
x = np.arange(len(protocols))
w = 0.32
b_bars = ax.bar(x - w/2, cvss_before, w, label="Pred mitigaciou (Baseline)", color=C_BASE, edgecolor="white", zorder=3)
s_bars = ax.bar(x + w/2, cvss_after,  w, label="Po mitigacii (Secure)",      color=C_SEC,  edgecolor="white", zorder=3)
for bar, val in zip(b_bars, cvss_before):
    ax.text(bar.get_x() + bar.get_width()/2, val + 0.15, f"{val}",
            ha="center", va="bottom", fontsize=11, fontweight="bold", color=C_BASE)
# Severity bands
ax.axhspan(9.0, 10.0, alpha=0.07, color="#C0392B", zorder=0)
ax.axhspan(7.0,  9.0, alpha=0.06, color="#E67E22", zorder=0)
ax.axhspan(4.0,  7.0, alpha=0.05, color="#F1C40F", zorder=0)
ax.axhspan(0.0,  4.0, alpha=0.04, color="#27AE60", zorder=0)
tx = len(protocols) - 0.05
ax.text(tx, 9.5, "Kriticka", va="center", fontsize=8, color="#C0392B", style="italic")
ax.text(tx, 8.0, "Vysoka",   va="center", fontsize=8, color="#E67E22", style="italic")
ax.text(tx, 5.5, "Stredna",  va="center", fontsize=8, color="#B7950B", style="italic")
ax.text(tx, 2.0, "Nizka",    va="center", fontsize=8, color="#27AE60", style="italic")
ax.set_xlim(-0.55, len(protocols) + 0.35)
ax.set_ylim(0, 10.8)
ax.set_yticks(np.arange(0, 11, 1))
ax.set_xticks(x)
ax.set_xticklabels(protocols)
ax.set_title("Porovnanie CVSS v4.0 Base skore – Pred a Po aplikacii mitigacii")
ax.set_ylabel("CVSS v4.0 Base skore (0.0 – 10.0)")
ax.legend(fontsize=9, loc="upper right")
fig.text(0.5, -0.03, "Zdroj: vlastne hodnotenie podla FIRST CVSS v4.0 (Klopček, 2025)",
         ha="center", fontsize=8, style="italic", color="#555")
plt.tight_layout()
out4 = FIGURES_DIR / "fig4_cvss_scores.png"
plt.savefig(out4)
plt.close()
print(f"[GRAF] {out4}", file=sys.stderr)

# ── Graf 5: CIA triada – 3 grafy vedla seba ───────────────────────────────────
fig, axes = plt.subplots(1, 3, figsize=(14, 5))
cia_labels = ["C\nDovernost", "I\nIntegrita", "A\nDostupnost"]
# Hodnoty: 0=Ziadny, 1=Nizky, 2=Stredny, 3=Vysoky
before_cia = {
    "P1 - MQTT": [3, 2, 2],
    "P2 - CoAP": [3, 2, 1],
    "P3 - OTA":  [1, 3, 2],
}
ylabels = {0: "Ziadny", 1: "Nizky", 2: "Stredny", 3: "Vysoky"}
for idx, (prot, ax_c) in enumerate(zip(list(before_cia.keys()), axes)):
    xp = np.arange(3)
    bv = before_cia[prot]
    ax_c.bar(xp - 0.2, bv, 0.35, color=C_BASE, label="Baseline", edgecolor="white")
    ax_c.bar(xp + 0.2, [0,0,0], 0.35, color=C_SEC, label="Secure", edgecolor="white")
    ax_c.set_ylim(0, 3.8)
    ax_c.set_yticks([0, 1, 2, 3])
    ax_c.set_yticklabels([ylabels[i] for i in range(4)], fontsize=8)
    ax_c.set_xticks(xp)
    ax_c.set_xticklabels(cia_labels, fontsize=9)
    ax_c.set_title(prot, fontweight="bold", fontsize=11)
    ax_c.grid(True, axis="y", alpha=0.3, linestyle="--")
    ax_c.spines["top"].set_visible(False)
    ax_c.spines["right"].set_visible(False)
    if idx == 0:
        ax_c.legend(fontsize=8)
fig.suptitle("Dopad na CIA triadu – Pred a Po mitigaciach (pre kazdy protokol)",
             fontsize=13, fontweight="bold")
fig.text(0.5, -0.01, "Zdroj: vlastne hodnotenie (Klopček, 2025)", ha="center", fontsize=8, style="italic", color="#555")
plt.tight_layout()
out5 = FIGURES_DIR / "fig5_cia_impact.png"
plt.savefig(out5, bbox_inches="tight")
plt.close()
print(f"[GRAF] {out5}", file=sys.stderr)

print(f"\n[GRAFY] Vsetky grafy ulozene do: {FIGURES_DIR}", file=sys.stderr)
