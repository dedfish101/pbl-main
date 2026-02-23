@echo off
echo ==========================================
echo   Starting NIDS Engine...
echo ==========================================
echo [!] IMPORTANT: You MUST run this file as Administrator.
echo     (Right-click run.bat -^> Run as Administrator)
echo.

call venv\Scripts\activate
python app.py

pause