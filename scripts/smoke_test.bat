@echo off
echo === SMOKE TEST ===
echo.
echo 1. MQTT publish test...
docker compose exec -T attacker mosquitto_pub -h mosquitto -p 1883 -t telemetry/test -m "hello" 2>nul && echo MQTT OK || echo MQTT FAIL
echo.
echo 2. CoAP GET test...
docker compose exec -T attacker coap-client -m get coap://coap/ 2>nul && echo CoAP OK || echo CoAP FAIL
echo.
echo 3. Checking artifacts...
if exist runs\%RUN_ID%\pcap\*.pcap (echo PCAP files found) else (echo No PCAP files yet)
if exist runs\%RUN_ID%\logs\*.log (echo Log files found) else (echo No log files yet)
echo.
echo === END ===
