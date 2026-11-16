@echo off
chcp 65001 >nul
title MINT - Cek Lingkungan
cd /d "%~dp0"
echo ============================================
echo   MINT - CEK LINGKUNGAN (Python, tshark,
echo   Docker, port 1883/8086/3000)
echo ============================================
echo.
python scripts\check_env.py
echo.
pause
