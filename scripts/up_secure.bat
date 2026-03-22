@echo off
REM Generic secure start of all overlays.
REM For reproducible thesis runs prefer Git Bash + Makefile or scripts\_run_all.sh.
cd %~dp0\..

if exist configs\ota\minisign.pub (
  powershell -Command "$pub=(Get-Content 'configs/ota/minisign.pub')[1].Trim(); $lines=Get-Content '.env'; $out=@(); foreach($line in $lines){ if($line -like 'MINISIGN_PUBKEY=*'){ $out += 'MINISIGN_PUBKEY=' + $pub } else { $out += $line } }; Set-Content '.env' $out"
) else (
  echo Upozornenie: configs\ota\minisign.pub neexistuje, OTA secure nebude plne aktivne.
)

docker compose -f docker-compose.yml -f docker-compose.mqtt-secure.yml -f docker-compose.coap-secure.yml -f docker-compose.ota-secure.yml build
docker compose -f docker-compose.yml -f docker-compose.mqtt-secure.yml -f docker-compose.coap-secure.yml -f docker-compose.ota-secure.yml up -d
