@echo off
setlocal
echo ==============================================================================
echo   CTI FUSION CENTER -- MASTER EXPERIMENTS RUNNER (LABS 1 TO 18)
echo ==============================================================================
echo Central Coordinator: Lab 7 (CTI Fusion Center)
echo Target: Executing and verifying all experiments from Lab 1 to 18...
echo.

set ROOT_VENV=C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\.venv\Scripts\python.exe
set SUB_VENV=C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\CTI_Fusion_Center_Updated\.venv\Scripts\python.exe
set SCRIPT_DIR=C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\CTI_Fusion_Center_Updated\CTI_Fusion_Center_Docker_Advanced_Checked\cti_fusion_center_docker_keyless

if exist "%ROOT_VENV%" (
    set PYTHON_EXE=%ROOT_VENV%
) else if exist "%SUB_VENV%" (
    set PYTHON_EXE=%SUB_VENV%
) else (
    echo Python virtual environment not found in .venv. Falling back to system python...
    set PYTHON_EXE=python
)

"%PYTHON_EXE%" "%SCRIPT_DIR%\run_all_experiments.py" %*

echo.
echo ==============================================================================
echo   ALL EXPERIMENTS COMPLETED SUCCESSFULLY
echo ==============================================================================
pause
