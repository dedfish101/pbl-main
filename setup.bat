@echo off
echo ==========================================
echo   NIDS Engine - Initial Setup Script
echo ==========================================
echo.
echo [*] Creating isolated Python Virtual Environment...
python -m venv venv

echo [*] Activating Virtual Environment...
call venv\Scripts\activate

echo [*] Installing dependencies from requirements.txt...
python -m pip install --upgrade pip
pip install -r requirements.txt

echo.
echo ==========================================
echo [!] CRITICAL REQUIREMENT FOR WINDOWS [!]
echo ==========================================
echo Scapy requires Npcap to capture raw packets on Windows.
echo 1. Download from: https://nmap.org/npcap/
echo 2. During installation
, YOU MUST check the box:
echo    "Install Npcap in WinPcap API-compatible Mode"
echo.
echo [*] Setup Complete. Press any key to exit.
pause