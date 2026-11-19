@echo off
setlocal
echo ==============================================================================
echo   CTI FUSION CENTER -- MASTER EXPERIMENTS RUNNER (LABS 8 TO 18)
echo ==============================================================================

set PYTHON_EXE=%~dp0\.venv\Scripts\python.exe
set SCRIPT_DIR=%~dp0\CTI_Fusion_Center_Docker_Advanced_Checked\cti_fusion_center_docker_keyless

if not exist "%PYTHON_EXE%" (
    set PYTHON_EXE=python
)

"%PYTHON_EXE%" "%SCRIPT_DIR%\run_all_experiments.py" %*
pause
