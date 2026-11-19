@echo off
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  echo Please run setup_cti.bat first.
  pause
  exit /b 1
)
if not exist .env copy .env.example .env
start "CTI Auto Sync - every 6 hours" cmd /k "cd /d ""%~dp0"" && call .venv\Scripts\activate.bat && python scheduler.py"
start "CTI Fusion Center Dashboard" cmd /k "cd /d ""%~dp0"" && call .venv\Scripts\activate.bat && streamlit run app.py"
