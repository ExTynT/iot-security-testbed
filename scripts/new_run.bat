@echo off
setlocal enabledelayedexpansion
cd /d %~dp0\..

for /f "usebackq delims=" %%a in (`powershell -Command "Get-Date -Format 'yyyyMMdd-HHmmss'"`) do (
    set RUN_ID=%%a
)

(
echo RUN_ID=%RUN_ID%
echo.
echo # MQTT ^(secure profil^)
echo MQTT_USER=device01
echo MQTT_PASS=device01pass
echo MQTT_CTRL_USER=controller01
echo MQTT_CTRL_PASS=controller01pass
echo.
echo # CoAP DTLS PSK ^(secure profil^)
echo COAP_PSK_IDENTITY=device01
echo COAP_PSK=supersecretpsk
echo COAP_HINT=CoAP
echo.
echo # minisign public key ^(secure OTA^)
echo MINISIGN_PUBKEY=
) > .env

mkdir "runs\%RUN_ID%\pcap" 2>nul
mkdir "runs\%RUN_ID%\logs" 2>nul
mkdir "runs\%RUN_ID%\results" 2>nul
mkdir "runs\%RUN_ID%\state" 2>nul

echo RUN_ID=%RUN_ID% pripravene v runs/%RUN_ID%/
