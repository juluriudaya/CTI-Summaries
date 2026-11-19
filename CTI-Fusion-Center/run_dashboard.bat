@echo off
setlocal
echo ==============================================================================
echo   CTI FUSION CENTER -- CENTRALIZED LABS DASHBOARD (LABS 7 TO 18)
echo ==============================================================================
echo.

set ROOT_VENV=%~dp0\..\.venv\Scripts\python.exe
set SUB_VENV=%~dp0\.venv\Scripts\python.exe
set SCRIPT_DIR=%~dp0\CTI_Fusion_Center_Docker_Advanced_Checked\cti_fusion_center_docker_keyless

cd /d "%SCRIPT_DIR%"

netstat -ano | findstr :8502 | findstr LISTENING >nul
if %errorlevel% equ 0 (
    echo [OK] Dashboard server is already active on port 8502.
    echo Opening browser at http://localhost:8502 ...
    start http://localhost:8502
    exit /b 0
)

echo Starting Streamlit server on http://localhost:8502 ...
start http://localhost:8502

if exist "%ROOT_VENV%" (
    echo Using Virtual Environment: %ROOT_VENV%
    "%ROOT_VENV%" -m streamlit run app.py --server.port 8502 --server.headless false
) else if exist "%SUB_VENV%" (
    echo Using Virtual Environment: %SUB_VENV%
    "%SUB_VENV%" -m streamlit run app.py --server.port 8502 --server.headless false
) else (
    streamlit run app.py --server.port 8502 --server.headless false
)

pause
