@echo off
chcp 65001 >nul
title MINT - Demo Replay Serangan
cd /d "%~dp0"
echo ============================================
echo   MINT - DEMO TANPA PERANGKAT
echo   Dashboard + replay data serangan (10x)
echo ============================================
echo.
rem Notifikasi Telegram & InfluxDB dikonfigurasi lewat file .env
rem (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, MINT_INFLUX_*).
start "MINT Dashboard" cmd /k python dashboard\app.py
timeout /t 3 >nul
echo Memutar ulang data/demo_serangan.csv (kecepatan 10x)...
echo (waktu replay otomatis disamakan dgn jam server - menu Anomali
echo  menampilkan waktu realtime, bukan tanggal lampau)
echo Buka http://localhost:5000 lalu login admin / mintadmin
echo.
python analyzer\live_analyzer.py --replay data\demo_serangan.csv --speed 10
echo.
echo Replay selesai - dashboard masih jalan di jendela lain.
pause
