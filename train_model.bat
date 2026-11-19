@echo off
title CTI Chat Bot - Deep Model Training Pipeline
echo ==============================================================================
echo   🚀 CTI CHAT BOT: DEEP MODEL TRAINING & RE-INDEXING PIPELINE
echo ==============================================================================
echo Training character and word n-gram vector models across all 18 labs,
echo 57 viva defense questions, and cyber threat intelligence signatures...
echo.

set ROOT_DIR=%~dp0
set VENV_PYTHON=%ROOT_DIR%.venv\Scripts\python.exe

if not exist "%VENV_PYTHON%" (
    set VENV_PYTHON=python
)

"%VENV_PYTHON%" "%ROOT_DIR%LLM_Threat_Chat_App\backend\train_model.py"

echo.
echo ==============================================================================
echo  Model weights serialized to: LLM_Threat_Chat_App\backend\trained_model_weights.joblib
echo ==============================================================================
pause
