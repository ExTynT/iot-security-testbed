@echo off
REM Spustenie baseline profilu
cd %~dp0\..
docker compose build
docker compose up -d
