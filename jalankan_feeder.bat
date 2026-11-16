@echo off
chcp 65001 >nul
title MINT - Feeder Sensor Simulasi (4 node ESP32)
cd /d "%~dp0"
echo ============================================
echo   MINT - FEEDER SENSOR (simulasi 4 node)
echo   iot/suhu  iot/jarak  iot/kamera  iot/cahaya
echo   nilai natural + foto JPEG + LWT status
echo ============================================
echo.
echo [i] Jalankan ini SETELAH broker (jalankan_broker.bat) dan
echo     dashboard (jalankan_dashboard.bat) hidup.
echo [i] Setelah jalan, "MQTT cache" di dashboard pindah HIJAU dan
echo     hitungan pesan naik terus.
echo.
python -c "import paho.mqtt, PIL" >nul 2>&1 || pip install paho-mqtt Pillow
python scripts\feeder_sensor.py %1
echo.
pause
