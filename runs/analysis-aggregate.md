# Agregovana uspesnost behov

Binarne PASS/FAIL vyhodnotenie je odvodene z `KPI_META` check funkcii a z poziadavky, aby run neobsahoval warningy v `summary.json`.

Celkovo: **30/30 PASS** (100.0%), warningy spolu: **0**.

| Scenar | Behy | PASS | FAIL | Warningy | Success rate |
|--------|------|------|------|----------|--------------|
| mqtt-baseline | 5 | 5 | 0 | 0 | 100.0% |
| mqtt-secure | 5 | 5 | 0 | 0 | 100.0% |
| coap-baseline | 5 | 5 | 0 | 0 | 100.0% |
| coap-secure | 5 | 5 | 0 | 0 | 100.0% |
| ota-baseline | 5 | 5 | 0 | 0 | 100.0% |
| ota-secure | 5 | 5 | 0 | 0 | 100.0% |
| celkom | 30 | 30 | 0 | 0 | 100.0% |

PASS/FAIL vychadza priamo z `KPI_META` check funkcii a zo vstupnych warningov z `summary.json`.
