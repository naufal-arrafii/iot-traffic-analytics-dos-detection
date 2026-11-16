@echo off
chcp 65001 >nul
title MINT - Broker MQTT (Mosquitto / fallback Python)
cd /d "%~dp0"
echo ============================================
echo   MINT - MENJALANKAN BROKER MQTT  :1883
echo   (WAJIB jalan paling duluan - tanpa ini
echo    "MQTT cache" di dashboard MERAH, 0 pesan)
echo ============================================
echo.

rem ---- 1) coba mosquitto.exe (instal resmi / via PATH) ----
set "MQ=%ProgramFiles%\mosquitto\mosquitto.exe"
if exist "%MQ%" goto :mosq
where mosquitto >nul 2>&1 && (set "MQ=mosquitto" & goto :mosq)

rem ---- 2) fallback: broker Python (amqtt) ----
echo [i] mosquitto.exe tidak ditemukan - pakai broker Python (amqtt).
echo [i] Butuh paho-mqtt + amqtt:  pip install paho-mqtt amqtt
python -c "import amqtt" >nul 2>&1 || pip install amqtt paho-mqtt
echo.
echo [OK] Broker Python listening 0.0.0.0:1883 (setara mosquitto.conf:
echo      allow_anonymous true, payload max 128 MB utk skenario S3).
echo [!] Biarkan jendela ini TERBUKA selama demo.
echo.
python scripts\broker_amqtt.py
goto :akhir

:mosq
echo [OK] Mosquitto resmi ditemukan: %MQ%
echo [i] Konfig: mosquitto\mosquitto.conf (listener 1883, anonim,
echo     message_size_limit 128 MB utk S3, max 200 koneksi).
echo [!] Biarkan jendela ini TERBUKA selama demo.
echo.
%MQ% -c mosquitto\mosquitto.conf -v
goto :akhir

:akhir
echo.
echo Broker berhenti. Tekan tombol apa saja utk menutup.
pause >nul
