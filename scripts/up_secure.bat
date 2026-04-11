@echo off
REM Vseobecne spustenie vsetkych secure overlayov.
REM Pre reprodukovatelne thesis behy preferuj Git Bash + Makefile alebo scripts\_run_all.sh.
cd %~dp0\..

if exist configs\ota\minisign.pub (
  echo OTA secure pouzije verejny kluc z configs\ota\minisign.pub
) else (
  echo Upozornenie: configs\ota\minisign.pub neexistuje, OTA secure nebude plne aktivne.
)

docker compose -f docker-compose.yml -f docker-compose.mqtt-secure.yml -f docker-compose.coap-secure.yml -f docker-compose.ota-secure.yml build
docker compose -f docker-compose.yml -f docker-compose.mqtt-secure.yml -f docker-compose.coap-secure.yml -f docker-compose.ota-secure.yml up -d
