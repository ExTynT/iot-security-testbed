@echo off
REM Spustenie secure profilu
cd %~dp0\..
docker compose -f docker-compose.yml -f docker-compose.secure.yml build
docker compose -f docker-compose.yml -f docker-compose.secure.yml up -d
