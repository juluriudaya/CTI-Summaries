@echo off
title CTI Chat Bot - Docker Container Launcher
echo ==============================================================================
echo   🐳 CTI CHAT BOT -- DOCKER CONTAINER LAUNCHER
echo ==============================================================================
echo Packaging and launching CTI Chat Bot as an isolated Docker container...
echo.

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not running. Please start Docker Desktop first.
    pause
    exit /b 1
)

echo [1/3] Stopping any previous cti-chat-bot container...
docker stop cti-chat-bot >nul 2>&1
docker rm cti-chat-bot >nul 2>&1

echo [2/3] Building CTI Chat Bot Docker image (cti-chat-bot:latest)...
docker build -t cti-chat-bot:latest .
if %errorlevel% neq 0 (
    echo [ERROR] Docker build failed.
    pause
    exit /b 1
)

echo.
echo [3/3] Running CTI Chat Bot container...
docker run -d ^
    --name cti-chat-bot ^
    --restart unless-stopped ^
    -p 8503:8503 ^
    -p 8005:8005 ^
    --add-host=host.docker.internal:host-gateway ^
    cti-chat-bot:latest

echo.
echo ==============================================================================
echo   ✅ CTI CHAT BOT DOCKER CONTAINER IS ONLINE!
echo ==============================================================================
echo   • Chatbot UI:   http://localhost:8503
echo   • Backend API:  http://localhost:8005/docs
echo   • Target DB:    mongodb://host.docker.internal:27017
echo ==============================================================================
echo.
ping -n 4 127.0.0.1 >nul
start http://localhost:8503

echo Inspecting container logs:
docker logs --tail 20 cti-chat-bot
pause
