@echo off
chcp 65001 >nul
title MINT - Analyzer Live (v9.2.5)
cd /d "%~dp0"
echo ============================================
echo   MINT - ANALYZER MANDIRI v9.2.5 (OPSIONAL)
echo   Dashboard v9.2.5 sudah memuat analyzer terintegrasi.
echo   Pakai jendela ini hanya utk sesi pcap/kalibrasi/replay.
echo.
echo   FIX v9.1: penulisan state.json kini tahan kunci
echo   (PermissionError WinError 5 saat dashboard membaca
echo   berkas yang sama TIDAK lagi membuat analyzer mati).
echo ============================================
echo Daftar interface bisa dilihat dengan: tshark -D
echo (interface Wi-Fi laptop biasanya bernama: Wi-Fi)
echo.
rem Notifikasi Telegram & InfluxDB dikonfigurasi lewat file .env
rem (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, MINT_INFLUX_*).
set /p IFACE=Nama interface capture (Enter = Wi-Fi): 
if "%IFACE%"=="" set IFACE=Wi-Fi
echo.
set INFLUX=
set /p PILIHINFLUX=Kirim metrik ke InfluxDB+Grafana? (y/N): 
if /I "%PILIHINFLUX%"=="y" set INFLUX=--influx
echo.
python analyzer\live_analyzer.py --iface "%IFACE%" %INFLUX%
echo.
echo Analyzer berhenti. Tekan tombol apa saja untuk menutup jendela...
pause >nul
