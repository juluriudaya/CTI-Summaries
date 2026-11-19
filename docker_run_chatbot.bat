@echo off
title CTI Chat Bot - Docker Container Launcher
echo ==============================================================================
echo   🐳 CTI CHAT BOT -- DOCKER CONTAINER LAUNCHER
echo ==============================================================================
echo.

set ROOT_DIR=%~dp0
set CHAT_DIR=%ROOT_DIR%LLM_Threat_Chat_App

cd /d "%CHAT_DIR%"
call docker_run_chatbot.bat
