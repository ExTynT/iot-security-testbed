# Agregovana uspesnost behov

Binarne PASS/FAIL vyhodnotenie je odvodene z `KPI_META` check funkcii a z poziadavky, aby run neobsahoval warningy v `summary.json`.

Celkovo: **127/177 PASS** (71.8%), warningy spolu: **75**.

| Scenar | Behy | PASS | FAIL | Warningy | Success rate |
|--------|------|------|------|----------|--------------|
| mqtt-baseline | 29 | 21 | 8 | 0 | 72.4% |
| mqtt-secure | 40 | 23 | 17 | 17 | 57.5% |
| coap-baseline | 22 | 21 | 1 | 0 | 95.5% |
| coap-secure | 30 | 22 | 8 | 21 | 73.3% |
| ota-baseline | 24 | 17 | 7 | 13 | 70.8% |
| ota-secure | 32 | 23 | 9 | 24 | 71.9% |
| celkom | 177 | 127 | 50 | 75 | 71.8% |

PASS/FAIL vychadza priamo z `KPI_META` check funkcii a zo vstupnych warningov z `summary.json`.