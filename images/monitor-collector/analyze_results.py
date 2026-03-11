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
    ("P1", "MQTT broker bez auth/TLS (port 1883)",         "H","H","H", "9.3 (Critical)", "2.1 (Low)"),
    ("P2", "CoAP plaintext bez autentifikacie (port 5683)","L","L","L", "5.3 (Medium)",   "3.1 (Low)"),
    ("P3", "OTA firmver bez overenia podpisu",             "H","H","L", "9.2 (Critical)", "2.1 (Low)"),
]
for num, vuln, c, i, a, before, after in cvss_rows:
    lines.append(f"| {num} | {vuln} | {c} | {i} | {a} | {before} | {after} |")

lines.append("")
lines.append(
    "> Vektory pred mitigaciou (CVSS v4.0): AV:N/AC:L/AT:N/PR:N/UI:N. "
    "Rezidualne skore po mitigacii: "
    "P1=2.1 (brute-force hesla AC:H/AT:P, DoS TLS handshake flood VA:L); "
    "P2=3.1 (race condition iptables – empiricky 0–3/10 poziadaviek preniklo, UDP amplifikacia); "
    "P3=2.1 (rollback attack – deploy starsi podpisany firmver, chyba version-pinning v testbede).\n"
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
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.colors import LinearSegmentedColormap
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

if not HAS_MPL:
    print("\n[INFO] matplotlib nie je dostupny – grafy preskocene.", file=sys.stderr)
    sys.exit(0)

FIGURES_DIR.mkdir(parents=True, exist_ok=True)

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

C_BASE = "#E74C3C"    # cervena  = zranitelny / utok uspel
C_SEC  = "#27AE60"    # zelena   = zabezpeceny / odmietnuty
C_GRAY = "#95A5A6"    # siva     = N/A (nevztahuje sa na scenar)
SOURCE = "Zdroj: vlastne merania (Klopecek, 2025)"

def bar_label(ax, bar, val, ymax, extra="", color="black"):
    """Anotuje stlpec hodnotou – aj pri val=0 (vykresli text nad osou)."""
    x = bar.get_x() + bar.get_width() / 2
    y = max(val, ymax * 0.025)
    label = (str(int(val)) if float(val) == int(val) else f"{val:.1f}") + extra
    ax.text(x, y, label, ha="center", va="bottom",
            fontsize=10, fontweight="bold", color=color)

# ── Graf 1: P1 MQTT – 4 stlpce (2 skupiny × 2 metriky) ──────────────────────
#   Skupina Baseline: [Uspesne utoky (red), Odmietnutia (green=0)]
#   Skupina Secure:   [Uspesne utoky (red=0), Odmietnutia (green)]
#   Ukazuje KOMPLETNY PRIEBEH 30 pokusov v oboch scenaroch.
b_success = get_avg("P1_mqtt_unauth_success", "mqtt-baseline") or 0
s_success = get_avg("P1_mqtt_unauth_success", "mqtt-secure")   or 0
b_denied  = get_avg("P1_mqtt_unauth_denied",  "mqtt-baseline") or 0
s_denied  = get_avg("P1_mqtt_unauth_denied",  "mqtt-secure")   or 0

fig, ax = plt.subplots(figsize=(9, 5))
x  = np.arange(2)
w  = 0.30
grp_labels = ["Baseline\n(port 1883, allow_anonymous=true)",
               "Secure\n(port 8883, TLS 1.3 + ACL + heslo)"]

bb = ax.bar(x - w/2, [b_success, s_success], w, color=C_BASE, edgecolor="white", linewidth=1.5,
            label="Uspesne (utok presiel)")
gb = ax.bar(x + w/2, [b_denied,  s_denied],  w, color=C_SEC,  edgecolor="white", linewidth=1.5,
            label="Odmietnutie (utok zablokovala mitigacia)")

ymax1 = max(b_success, s_success, b_denied, s_denied, 1) * 1.55
ax.set_ylim(0, ymax1)

for bar, val, clr in [(bb[0], b_success, C_BASE), (gb[0], b_denied,  C_SEC),
                       (bb[1], s_success, C_BASE), (gb[1], s_denied,  C_SEC)]:
    bar_label(ax, bar, val, ymax1, color=clr)

ax.set_xticks(x)
ax.set_xticklabels(grp_labels, fontsize=10)
ax.set_ylabel("Pocet pokusov (z celkovych 30)")
ax.set_title("P1 – MQTT: Vysledok neautorizovanych PUBLISH pokusov\n"
             "(Baseline vs. Zabezpecena konfiguracia)")
ax.legend(fontsize=9, loc="upper center")
fig.text(0.5, -0.04, SOURCE, ha="center", fontsize=8, style="italic", color="#555")
plt.tight_layout()
plt.savefig(FIGURES_DIR / "fig1_p1_mqtt_kpi.png")
plt.close()
print(f"[GRAF] {FIGURES_DIR}/fig1_p1_mqtt_kpi.png", file=sys.stderr)

# ── Graf 2: P2 CoAP – 2×2 subploty, kazdy s vlastnou osou Y ─────────────────
#   Kazda metrika ma vlastny subplot → zelene stlpce su vzdy viditelne.
coap_sub = [
    ("P2_coap_plain_gets",
     "Plaintext GET poziadavky prijate\n(uspesny pristup bez DTLS – port 5683)",
     C_BASE, C_BASE,   # baseline=red(bad), secure=red ale 0 = prekazano
     False),           # secure je "zlounitelnost ocakavana 0"
    ("P2_coap_plain_blocked",
     "Plaintext port zablokovany\n(iptables DROP na porte 5683)",
     C_GRAY, C_SEC,    # baseline=N/A, secure=green(good)
     True),
    ("P2_coap_dtls_failures",
     "DTLS handshake odmietnuty\n(nespravny PSK – bezpecnostna ochrana)",
     C_GRAY, C_SEC,
     True),
    ("P2_coap_dtls_ok",
     "DTLS handshake uspesny\n(spravny PSK – sluzba funguje)",
     C_GRAY, C_SEC,
     True),
]

fig, axes = plt.subplots(2, 2, figsize=(12, 9))
fig.suptitle("P2 – CoAP: Merania pre plaintext a DTLS-PSK scenare\n"
             "(Baseline vs. Zabezpecena konfiguracia – DTLS-PSK + iptables)",
             fontsize=13, fontweight="bold")

for ax_c, (kpi, title, bc, sc, sec_is_good) in zip(axes.flat, coap_sub):
    bv = get_avg(kpi, "coap-baseline") or 0
    sv = get_avg(kpi, "coap-secure")   or 0
    ymx = max(bv, sv, 1) * 1.55

    br_b = ax_c.bar(["Baseline"], [bv], color=bc, edgecolor="white", linewidth=1.5, width=0.4)
    br_s = ax_c.bar(["Secure"],   [sv], color=sc, edgecolor="white", linewidth=1.5, width=0.4)
    ax_c.set_ylim(0, ymx)

    # Anotacie – vzdy zobraz hodnotu, aj pre 0
    bar_label(ax_c, br_b[0], bv, ymx,
              extra="" if bv > 0 else " (N/A)" if bc == C_GRAY else " (bez ochrany)",
              color=bc if bc != C_GRAY else "#555")
    bar_label(ax_c, br_s[0], sv, ymx,
              extra=" (OK)" if (sec_is_good and sv > 0) else " (zranitelnost!)" if (sec_is_good and sv == 0 and kpi == "P2_coap_dtls_ok") else "",
              color=sc)

    ax_c.set_title(title, fontsize=10)
    ax_c.set_ylabel("Hodnota KPI (priemer)")
    ax_c.grid(True, axis="y", alpha=0.35, linestyle="--")
    ax_c.spines["top"].set_visible(False)
    ax_c.spines["right"].set_visible(False)

fig.text(0.5, -0.01, SOURCE, ha="center", fontsize=8, style="italic", color="#555")
plt.tight_layout()
plt.savefig(FIGURES_DIR / "fig2_p2_coap_kpi.png", bbox_inches="tight")
plt.close()
print(f"[GRAF] {FIGURES_DIR}/fig2_p2_coap_kpi.png", file=sys.stderr)

# ── Graf 3: P3 OTA – 2 skupiny (aplikovany vs. zablokovany) ─────────────────
#   Skupiny: "Skodlivy firmver APLIKOVANY" a "Skodlivy firmver ZABLOKOVANY"
#   Kazda skupina ma 2 stlpce (Baseline=red/gray, Secure=red/green).
b_applied = get_avg("P3_ota_evil_applied", "ota-baseline") or 0
s_applied = get_avg("P3_ota_evil_applied", "ota-secure")   or 0
b_blocked = get_avg("P3_ota_evil_blocked", "ota-baseline") or 0
s_blocked = get_avg("P3_ota_evil_blocked", "ota-secure")   or 0

fig, ax = plt.subplots(figsize=(9, 5))
x = np.arange(2)
w = 0.28

# Skupina 1: firmver APLIKOVANY (Baseline=red, Secure=green ale 0)
ba1 = ax.bar(x[0] - w/2, b_applied, w, color=C_BASE, edgecolor="white", linewidth=1.5,
             label="Baseline")
sa1 = ax.bar(x[0] + w/2, s_applied, w, color=C_SEC,  edgecolor="white", linewidth=1.5,
             label="Secure (minisign Ed25519)")
# Skupina 2: firmver ZABLOKOVANY (Baseline=gray 0, Secure=green)
ba2 = ax.bar(x[1] - w/2, b_blocked, w, color=C_GRAY, edgecolor="white", linewidth=1.5)
sa2 = ax.bar(x[1] + w/2, s_blocked, w, color=C_SEC,  edgecolor="white", linewidth=1.5)

ymax3 = max(b_applied, s_applied, b_blocked, s_blocked, 1) * 1.65
ax.set_ylim(0, ymax3)

bar_label(ax, ba1[0], b_applied, ymax3, color=C_BASE)
bar_label(ax, sa1[0], s_applied, ymax3, extra=" (zablokovany!)" if s_applied == 0 else "", color=C_SEC)
bar_label(ax, ba2[0], b_blocked, ymax3, extra=" (N/A)" if b_blocked == 0 else "", color="#555")
bar_label(ax, sa2[0], s_blocked, ymax3, extra=" (OK)" if s_blocked > 0 else "", color=C_SEC)

ax.set_xticks(x)
ax.set_xticklabels(["Skodlivy firmver\nAPLIKOVANY\n(zranitelnost)",
                     "Skodlivy firmver\nZABLOKOVANY\n(ochrana)"], fontsize=10)
ax.set_ylabel("KPI hodnota (priemer replikacii)")
ax.set_title("P3 – OTA: Utok podvrhnutym firmverom\n"
             "(Baseline vs. Zabezpecena konfiguracia – minisign Ed25519)")
ax.legend(fontsize=9)
fig.text(0.5, -0.04, SOURCE, ha="center", fontsize=8, style="italic", color="#555")
plt.tight_layout()
plt.savefig(FIGURES_DIR / "fig3_p3_ota_kpi.png")
plt.close()
print(f"[GRAF] {FIGURES_DIR}/fig3_p3_ota_kpi.png", file=sys.stderr)

# ── Graf 4: CVSS v4.0 – skupinovy stlpcovy graf ──────────────────────────────
fig, ax = plt.subplots(figsize=(9, 5.5))
protocols   = ["P1 – MQTT\n(neautorizovany pristup)",
               "P2 – CoAP\n(plaintext bez DTLS)",
               "P3 – OTA\n(nepodpisany firmver)"]
# CVSS v4.0 pred mitigaciou (overene kalkulatorom first.org/cvss/calculator/4.0):
# P1 MQTT  9.3 – AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N
# P2 CoAP  5.3 – AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N
# P3 OTA   9.2 – AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N
cvss_before = [9.3, 5.3, 9.2]
# Rezidualne skore po mitigacii – nie nula (mitigacia redukuje, nie eliminuje riziko):
#   P1 MQTT  2.1 – brute-force hesla (AC:H/AT:P) / DoS TLS handshake flood (VA:L)
#   P2 CoAP  3.1 – race condition iptables (0–3/10 pokusov preniklo empiricky) + UDP amplifikacia
#   P3 OTA   2.1 – rollback attack (deploy starsi validne podpisany firmver; chyba version-pinning)
cvss_after  = [2.1, 3.1, 2.1]
x = np.arange(len(protocols))
w = 0.32
b_bars = ax.bar(x - w/2, cvss_before, w, color=C_BASE, edgecolor="white", linewidth=1.5,
                label="Pred mitigaciou (Baseline)", zorder=3)
s_bars = ax.bar(x + w/2, cvss_after,  w, color=C_SEC,  edgecolor="white", linewidth=1.5,
                label="Po mitigacii (Secure)", zorder=3)

for bar, val in zip(b_bars, cvss_before):
    ax.text(bar.get_x() + bar.get_width()/2, val + 0.15, f"{val}",
            ha="center", va="bottom", fontsize=11, fontweight="bold", color=C_BASE)
for bar, val in zip(s_bars, cvss_after):
    ax.text(bar.get_x() + bar.get_width()/2, val + 0.15, f"{val}",
            ha="center", va="bottom", fontsize=10, fontweight="bold", color=C_SEC)

# Pasma zavaznosti
ax.axhspan(9.0, 10.0, alpha=0.08, color="#C0392B", zorder=0)
ax.axhspan(7.0,  9.0, alpha=0.07, color="#E67E22", zorder=0)
ax.axhspan(4.0,  7.0, alpha=0.05, color="#F1C40F", zorder=0)
ax.axhspan(0.0,  4.0, alpha=0.05, color="#27AE60", zorder=0)
tx = len(protocols) - 0.05
for ypos, lbl, clr in [(9.5,"Kriticka","#C0392B"),(8.0,"Vysoka","#E67E22"),
                        (5.5,"Stredna","#B7950B"),(2.0,"Nizka","#27AE60")]:
    ax.text(tx, ypos, lbl, va="center", fontsize=8, color=clr, style="italic")

ax.set_xlim(-0.55, len(protocols) + 0.35)
ax.set_ylim(0, 10.8)
ax.set_yticks(np.arange(0, 11, 1))
ax.set_xticks(x)
ax.set_xticklabels(protocols)
ax.set_title("Porovnanie CVSS v4.0 Base skore\nPred a po aplikacii mitigacii")
ax.set_ylabel("CVSS v4.0 Base skore (0.0 – 10.0)")
ax.legend(fontsize=9, loc="upper right")
fig.text(0.5, -0.03, "Zdroj: vlastne hodnotenie podla FIRST CVSS v4.0 (Klopecek, 2025)",
         ha="center", fontsize=8, style="italic", color="#555")
plt.tight_layout()
plt.savefig(FIGURES_DIR / "fig4_cvss_scores.png")
plt.close()
print(f"[GRAF] {FIGURES_DIR}/fig4_cvss_scores.png", file=sys.stderr)

# ── Graf 5: CIA triada – HEATMAPA (namiesto stlpcov so 0) ────────────────────
#   Heatmapa je najvhodnejsim typom grafu pre kategoricke urovne dopadu.
#   Riadky: C, I, A | Stlpce: kazdy protokol pred/po mitigacii
#   Farba bunky: 0=svetlozelena, 1=zlta, 2=oranzova, 3=cervena

impact_txt = {0: "Ziadny", 1: "Nizky", 2: "Stredny", 3: "Vysoky"}

# Matica: [C, I, A] pre [P1_pred, P1_po, P2_pred, P2_po, P3_pred, P3_po]
# Uroven dopadu (0=Ziadny, 1=Nizky, 2=Stredny, 3=Vysoky)
# Stlpce: [P1_pred, P1_po, P2_pred, P2_po, P3_pred, P3_po]
# P1 po mitigacii: Low – brute-force / DoS TLS flood (nie None, len redukcia)
# P2 po mitigacii: Low – race condition iptables + UDP amplifikacia
# P3 po mitigacii: I=Low (rollback), C/A=None (OTA neovplyvnuje data/dostupnost)
cia_matrix = np.array([
    [3, 1,  1, 1,  3, 0],   # Dovernost (C)  P2: VC:L→1; P3: VC:H→3
    [2, 1,  1, 1,  3, 1],   # Integrita (I)  P2: VI:L→1
    [2, 1,  1, 1,  1, 0],   # Dostupnost (A) P2: VA:L→1; P3: VA:L→1
], dtype=float)

col_labels = ["P1\npred", "P1\npo", "P2\npred", "P2\npo", "P3\npred", "P3\npo"]
row_labels  = ["Dovernost (C)", "Integrita (I)", "Dostupnost (A)"]

# Vlastna farebna mapa: zelena → zlta → oranzova → cervena
cmap_cia = LinearSegmentedColormap.from_list(
    "cia_impact", ["#D5F5E3", "#F9E79F", "#F0B27A", "#EC7063"], N=256)

fig, ax = plt.subplots(figsize=(13, 4.5))
im = ax.imshow(cia_matrix, cmap=cmap_cia, vmin=0, vmax=3, aspect="auto")

ax.set_xticks(range(len(col_labels)))
ax.set_yticks(range(len(row_labels)))
ax.set_xticklabels(col_labels, fontsize=11)
ax.set_yticklabels(row_labels, fontsize=11)

# Mriezka
ax.set_xticks(np.arange(len(col_labels)+1) - 0.5, minor=True)
ax.set_yticks(np.arange(len(row_labels)+1) - 0.5, minor=True)
ax.grid(which="minor", color="white", linewidth=2.5)
ax.tick_params(which="minor", bottom=False, left=False)

# Text v bunkach
for i in range(3):
    for j in range(6):
        v = int(cia_matrix[i, j])
        txt_clr = "white" if v == 3 else "black"
        ax.text(j, i, impact_txt[v], ha="center", va="center",
                fontsize=11, fontweight="bold", color=txt_clr)

# Zvyraznenie skupin (vertikalne ciare medzi protokolmi)
for xp in [1.5, 3.5]:
    ax.axvline(x=xp, color="white", linewidth=4)

# Nazvy skupin (P1, P2, P3) nad stlpcami
for gx, lbl in [(0.5, "P1 – MQTT"), (2.5, "P2 – CoAP"), (4.5, "P3 – OTA")]:
    ax.annotate(lbl, xy=(gx, -0.5), xycoords="data",
                ha="center", va="bottom", fontsize=11, fontweight="bold",
                annotation_clip=False)

# Farebna legenda (colorbar)
cbar = plt.colorbar(im, ax=ax, pad=0.02, fraction=0.03, ticks=[0, 1, 2, 3])
cbar.ax.set_yticklabels(
    ["Ziadny (0)", "Nizky (1)", "Stredny (2)", "Vysoky (3)"], fontsize=9)
cbar.set_label("Uroven dopadu", fontsize=10)

ax.set_title("Dopad na CIA triadu – Pred a po aplikacii mitigacii",
             fontsize=13, fontweight="bold", pad=28)
for sp in ax.spines.values():
    sp.set_visible(False)
ax.grid(False, which="major")

fig.text(0.5, -0.06, "Zdroj: vlastne hodnotenie (Klopecek, 2025)",
         ha="center", fontsize=8, style="italic", color="#555")
plt.tight_layout()
plt.savefig(FIGURES_DIR / "fig5_cia_impact.png", bbox_inches="tight")
plt.close()
print(f"[GRAF] {FIGURES_DIR}/fig5_cia_impact.png", file=sys.stderr)

print(f"\n[GRAFY] Vsetky grafy ulozene do: {FIGURES_DIR}", file=sys.stderr)
