@echo off
setlocal enabledelayedexpansion
title CTI Fusion Center - Complete Enterprise System Suite

echo ==============================================================================
echo   🛡️  CTI FUSION CENTER & CTI-AI SUITE -- MASTER UNIFIED LAUNCHER
echo ==============================================================================
echo Central Hub: Labs 1 to 18 + Autonomous CTI-AI Chatbot & Mitigation Engine
echo.

set "ROOT_DIR=%~dp0"
set "VENV_PYTHON=%ROOT_DIR%.venv\Scripts\python.exe"
set "DASHBOARD_DIR=%ROOT_DIR%CTI_Fusion_Center_Updated\CTI_Fusion_Center_Docker_Advanced_Checked\cti_fusion_center_docker_keyless"
set "CHAT_BACKEND=%ROOT_DIR%LLM_Threat_Chat_App\backend"
set "CHAT_FRONTEND=%ROOT_DIR%LLM_Threat_Chat_App\frontend"

if not exist "%VENV_PYTHON%" (
    echo [ERROR] Virtual environment python not found at: %VENV_PYTHON%
    echo Falling back to system python...
    set "VENV_PYTHON=python"
)

echo [1/3] Checking CTI-AI Backend on port 8005...
netstat -ano | findstr :8005 | findstr LISTENING >nul
if %errorlevel% equ 0 (
    echo       [ACTIVE] FastAPI CTI-AI Backend is already running on port 8005.
) else (
    echo       [STARTING] Launching FastAPI CTI-AI Backend on port 8005...
    start "CTI-AI Backend (Port 8005)" /d "%CHAT_BACKEND%" cmd /k ""%VENV_PYTHON%" -m uvicorn main:app --host 0.0.0.0 --port 8005"
    ping -n 3 127.0.0.1 >nul
)

echo.
echo [2/3] Checking CTI SUMMARIES Dashboard on port 8502...
netstat -ano | findstr :8502 | findstr LISTENING >nul
if %errorlevel% equ 0 (
    echo       [ACTIVE] Streamlit Dashboard is already running on port 8502.
) else (
    echo       [STARTING] Launching CTI SUMMARIES Dashboard on port 8502...
    start "CTI SUMMARIES Dashboard (Port 8502)" /d "%DASHBOARD_DIR%" cmd /k ""%VENV_PYTHON%" -m streamlit run app.py --server.port 8502 --server.headless true --browser.gatherUsageStats false"
    ping -n 3 127.0.0.1 >nul
)

echo.
echo [3/3] Checking CTI Chat Bot on port 8503...
netstat -ano | findstr :8503 | findstr LISTENING >nul
if %errorlevel% equ 0 (
    echo       [ACTIVE] Streamlit Chat Interface is already running on port 8503.
) else (
    echo       [STARTING] Launching CTI Chat Bot on port 8503...
    start "CTI Chat Bot (Port 8503)" /d "%CHAT_FRONTEND%" cmd /k ""%VENV_PYTHON%" -m streamlit run chat_app.py --server.port 8503 --server.headless true --browser.gatherUsageStats false"
    ping -n 3 127.0.0.1 >nul
)

echo.
echo ==============================================================================
echo   ALL SERVICES SYNCHRONIZED AND ONLINE
echo ==============================================================================
echo   * CTI SUMMARIES Dashboard:       http://localhost:8502
echo   * CTI Chat Bot:                  http://localhost:8503
echo   * FastAPI OpenAPI Documentation: http://localhost:8005/docs
echo ==============================================================================
echo.
echo Waiting 4 seconds for web sockets to initialize...
ping -n 5 127.0.0.1 >nul

echo Launching default web browser...
start http://localhost:8502
start http://localhost:8503

echo.
echo NOTE: If your browser displays "This site can't be reached", please press F5 (Refresh) once the server finishes initializing!
echo Done. All three servers are running in persistent terminal windows.
