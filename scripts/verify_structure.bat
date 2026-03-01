@echo off
echo === VERIFIKACIA STRUKTURY PROJEKTU ===
echo.

echo 1. Kontrola adresarov...
for %%d in (configs configs\mqtt configs\mqtt\baseline configs\mqtt\secure configs\mqtt\secure\certs configs\coap configs\ota configs\ota\repo images images\dut images\attacker images\sniffer images\monitor-collector images\coap-server scripts runs) do (
    if exist %%d (echo   [OK] %%d) else (echo   [CHYBA] %%d)
)

echo.
echo 2. Kontrola konfiguracii...
for %%f in (configs\mqtt\baseline\mosquitto.conf configs\mqtt\secure\mosquitto.conf configs\mqtt\secure\aclfile configs\ota\repo\manifest.json) do (
    if exist %%f (echo   [OK] %%f) else (echo   [CHYBA] %%f)
)

echo.
echo 3. Kontrola Dockerfiles...
for %%f in (images\dut\Dockerfile images\attacker\Dockerfile images\sniffer\Dockerfile images\monitor-collector\Dockerfile images\coap-server\Dockerfile) do (
    if exist %%f (echo   [OK] %%f) else (echo   [CHYBA] %%f)
)

echo.
echo 4. Kontrola docker-compose...
for %%f in (docker-compose.yml docker-compose.secure.yml) do (
    if exist %%f (echo   [OK] %%f) else (echo   [CHYBA] %%f)
)

echo.
echo 5. Kontrola skriptov...
for %%f in (scripts\new_run.bat scripts\up_baseline.bat scripts\up_secure.bat scripts\smoke_test.bat) do (
    if exist %%f (echo   [OK] %%f) else (echo   [CHYBA] %%f)
)

echo.
echo 6. Kontrola .env a RUN_ID...
if exist .env (
    echo   [OK] .env existuje
    type .env | findstr "RUN_ID"
) else (
    echo   [INFO] .env neexistuje - spusti scripts\new_run.bat
)

echo.
echo 7. Kontrola TLS certifikatov...
if exist configs\mqtt\secure\certs\ca.crt (
    echo   [OK] CA certifikat existuje
) else (
    echo   [INFO] TLS certifikaty neexistuju - budu generovane pri prvom spusteni
)

echo.
echo === VERIFIKACIA DOKONCENA ===
echo.
echo Pre spustenie testu:
echo   1. Uisti sa ze Docker Desktop bezi
echo   2. scripts\new_run.bat
echo   3. scripts\up_baseline.bat
echo   4. scripts\smoke_test.bat
