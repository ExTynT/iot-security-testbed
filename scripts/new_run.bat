@echo off
setlocal enabledelayedexpansion

for /f "usebackq delims=" %%a in (`powershell -Command "Get-Date -Format 'yyyyMMdd-HHmm'"`) do (
    set RUN_ID=%%a
)

(
echo RUN_ID=%RUN_ID%
echo # CoAP DTLS PSK (secure profil)
echo COAP_PSK_IDENTITY=device01
echo COAP_PSK=supersecretpsk
echo COAP_HINT=CoAP
echo # minisign public key (secure OTA) – doplníš neskôr
echo MINISIGN_PUBKEY=
) > .env

mkdir "runs\%RUN_ID%\pcap" 2>nul
mkdir "runs\%RUN_ID%\logs" 2>nul
mkdir "runs\%RUN_ID%\results" 2>nul

echo RUN_ID=%RUN_ID% pripravené v runs/%RUN_ID%/
