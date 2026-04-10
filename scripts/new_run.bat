@echo off
setlocal enabledelayedexpansion
cd /d %~dp0\..

for /f "usebackq delims=" %%a in (`powershell -Command "Get-Date -Format 'yyyyMMdd-HHmmss'"`) do (
    set RUN_ID=%%a
)

for /f "usebackq delims=" %%a in (`powershell -Command "[guid]::NewGuid().ToString('N')"`) do (
    set MQTT_DEVICE_PASSWORD=%%a
)
for /f "usebackq delims=" %%a in (`powershell -Command "[guid]::NewGuid().ToString('N')"`) do (
    set MQTT_CONTROLLER_PASSWORD=%%a
)
for /f "usebackq delims=" %%a in (`powershell -Command "[guid]::NewGuid().ToString('N')"`) do (
    set COAP_PSK=%%a
)

(
echo RUN_ID=%RUN_ID%
) > .env

mkdir "runs\%RUN_ID%\pcap" 2>nul
mkdir "runs\%RUN_ID%\logs" 2>nul
mkdir "runs\%RUN_ID%\results" 2>nul
mkdir "runs\%RUN_ID%\state" 2>nul
mkdir "runs\%RUN_ID%\secrets" 2>nul

> "runs\%RUN_ID%\secrets\mqtt_device_password.txt" echo %MQTT_DEVICE_PASSWORD%
> "runs\%RUN_ID%\secrets\mqtt_controller_password.txt" echo %MQTT_CONTROLLER_PASSWORD%
> "runs\%RUN_ID%\secrets\coap_psk.txt" echo %COAP_PSK%

echo RUN_ID=%RUN_ID% pripravene v runs/%RUN_ID%/
