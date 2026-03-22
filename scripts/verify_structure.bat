@echo off
cd /d %~dp0\..
echo === VERIFIKACIA STRUKTURY PROJEKTU ===
echo.

echo 1. Kontrola adresarov...
for %%d in (configs configs\mqtt configs\mqtt\baseline configs\mqtt\secure configs\mqtt\secure\certs configs\coap configs\ota configs\ota\repo configs\ota\evil images images\dut images\attacker images\sniffer images\monitor-collector images\coap-server scripts runs) do (
    if exist %%d (echo   [OK] %%d) else (echo   [CHYBA] %%d)
)

echo.
echo 2. Kontrola konfiguracii...
for %%f in (configs\mqtt\baseline\mosquitto.conf configs\mqtt\secure\mosquitto.conf configs\mqtt\secure\aclfile configs\ota\repo\manifest.json configs\ota\nginx-official.conf configs\ota\nginx-evil.conf) do (
    if exist %%f (echo   [OK] %%f) else (echo   [CHYBA] %%f)
)

echo.
echo 3. Kontrola Dockerfiles...
for %%f in (images\dut\Dockerfile images\attacker\Dockerfile images\sniffer\Dockerfile images\monitor-collector\Dockerfile images\coap-server\Dockerfile) do (
    if exist %%f (echo   [OK] %%f) else (echo   [CHYBA] %%f)
)

echo.
echo 4. Kontrola docker-compose...
for %%f in (docker-compose.yml docker-compose.mqtt-secure.yml docker-compose.coap-secure.yml docker-compose.ota-secure.yml) do (
    if exist %%f (echo   [OK] %%f) else (echo   [CHYBA] %%f)
)

echo.
echo 5. Kontrola skriptov...
for %%f in (scripts\new_run.bat scripts\new_run.sh scripts\set_minisign_pubkey.sh scripts\wait_ready.sh scripts\ota_secure_control_signed.sh scripts\mqtt_secure_control_auth.sh scripts\run_case.sh scripts\analyze_runs.sh) do (
    if exist %%f (echo   [OK] %%f) else (echo   [CHYBA] %%f)
)

echo.
echo 6. Kontrola .env a RUN_ID...
if exist .env (
    echo   [OK] .env existuje
    type .env | findstr "RUN_ID"
) else (
    echo   [INFO] .env neexistuje - spusti scripts\new_run.bat alebo scripts\new_run.sh
)

echo.
echo 7. Kontrola TLS certifikatov...
if exist configs\mqtt\secure\certs\ca.crt (
    echo   [OK] CA certifikat existuje
) else (
    echo   [INFO] TLS certifikaty neexistuju - skontroluj configs\mqtt\secure\certs
)

echo.
echo === VERIFIKACIA DOKONCENA ===
