@echo off
title CTI Threat Intelligence LLM Chat & Auto-Mitigator
echo =======================================================================
echo   CTI-AI -- LLM/SLM THREAT CHAT & AUTONOMOUS MITIGATOR
echo =======================================================================
echo.

cd /d "%~dp0"

echo [1/2] Launching FastAPI Backend on port 8005...
start "CTI Chat Backend" ..\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 0.0.0.0 --port 8005

timeout /t 3 /nobreak >nul

echo [2/2] Launching Streamlit Chat Frontend on port 8503...
start "CTI Chat Frontend" ..\.venv\Scripts\python.exe -m streamlit run frontend\chat_app.py --server.port 8503 --server.address 0.0.0.0

echo.
echo Application started successfully!
echo   * Backend API:  http://localhost:8005/docs
echo   * Chat Console: http://localhost:8503
echo =======================================================================
pause
