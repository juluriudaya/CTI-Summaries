@echo off
setlocal
echo ==============================================================================
echo   STARTING LAB 7 (CTI FUSION CENTER) WITH CONNECTED EXPERIMENTS 8 TO 18
echo ==============================================================================
echo Opening Streamlit Central Analyst Console on http://localhost:8501 ...
echo.

set PYTHON_EXE=C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\CTI_Fusion_Center_Updated\.venv\Scripts\python.exe
set SCRIPT_DIR=C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\CTI_Fusion_Center_Updated\CTI_Fusion_Center_Docker_Advanced_Checked\cti_fusion_center_docker_keyless

cd /d "%SCRIPT_DIR%"

if exist "%PYTHON_EXE%" (
    "%PYTHON_EXE%" -m streamlit run app.py
) else (
    streamlit run app.py
)

pause
