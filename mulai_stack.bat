@echo off
chcp 65001 >nul
title MINT - Stack Docker (Mosquitto + InfluxDB + Grafana)
cd /d "%~dp0"
echo ============================================
echo   MINT - Menjalankan stack Docker
echo   Mosquitto :1883   InfluxDB :8086   Grafana :3000
echo ============================================
echo.

rem ---- cek Docker terpasang + daemon hidup ----
docker info >nul 2>&1
if errorlevel 1 (
  echo [X] Docker TIDAK terpasang atau Docker Desktop belum jalan.
  echo.
  echo     Pilih salah satu jalur:
  echo     1. DENGAN Docker : pasang Docker Desktop, buka sampai status
  echo        "running", lalu jalankan lagi file ini.
  echo     2. TANPA Docker  : jalankan jalankan_broker.bat  - broker :1883
  echo        lalu jalankan_dashboard.bat - web :5000.
  echo        InfluxDB + Grafana opsional, inti demo tetap jalan penuh.
  echo.
  pause
  exit /b 1
)

rem ---- compose v2 ^(docker compose^) atau v1 ^(docker-compose^) ----
docker compose version >nul 2>&1
if errorlevel 1 (
  docker-compose up -d
) else (
  docker compose up -d
)

echo.
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo.
echo Grafana juga tampil di menu 'Grafana' dashboard ^(iframe^).
echo Jika semua UP, lanjutkan:
echo   jalankan_dashboard.bat  - dashboard :5000 + analyzer terintegrasi
echo   jalankan_feeder.bat     - simulasi 4 node sensor tanpa ESP32
echo.
pause
