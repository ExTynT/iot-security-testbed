# Agregovana uspesnost behov

Binarne PASS/FAIL vyhodnotenie je odvodene z `KPI_META` check funkcii a z poziadavky, aby run neobsahoval warningy v `summary.json`.

Celkovo: **6/6 PASS** (100.0%), warningy spolu: **0**.

| Scenar | Behy | PASS | FAIL | Warningy | Success rate |
|--------|------|------|------|----------|--------------|
| mqtt-baseline | 1 | 1 | 0 | 0 | 100.0% |
| mqtt-secure | 1 | 1 | 0 | 0 | 100.0% |
| coap-baseline | 1 | 1 | 0 | 0 | 100.0% |
| coap-secure | 1 | 1 | 0 | 0 | 100.0% |
| ota-baseline | 1 | 1 | 0 | 0 | 100.0% |
| ota-secure | 1 | 1 | 0 | 0 | 100.0% |
| celkom | 6 | 6 | 0 | 0 | 100.0% |

PASS/FAIL vychadza priamo z `KPI_META` check funkcii a zo vstupnych warningov z `summary.json`.