@echo off
chcp 65001 >nul
title MINT - Web Dashboard
cd /d "%~dp0"
echo ============================================
echo   MINT v9.2.5 - WEB DASHBOARD + GRAFIK PPS REALTIME
echo   login: admin / mintadmin
echo   Buka http://localhost:5000  (menu: Serangan utk uji S1-S4)
echo   Tidak perlu jalankan_analyzer.bat terpisah - PPS/BPS
echo   otomatis terbaca. Metrik tshark + MQTT DIGABUNG sehingga
echo   serangan dari menu Serangan pasti terlihat di grafik/anomali.
echo   BARU v9.2.5: sidebar bergrup, peringatan serangan di semua halaman,
echo   Telegram dikonfigurasi langsung dari web, jaringan dirapikan
echo   (broker .101, node .102-.105), S3 payload >200 KB (maks 512).
echo ============================================
echo.
rem Telegram: isi Token Bot & Chat ID LANGSUNG dari web (menu Pengaturan)
rem setelah login admin - tersimpan otomatis di .env. InfluxDB tetap di .env.
python dashboard\app.py
echo.
pause
