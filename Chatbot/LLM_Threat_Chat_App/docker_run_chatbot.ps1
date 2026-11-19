# CTI Chat Bot - Docker Container Launcher
$Host.UI.RawUI.WindowTitle = "CTI Chat Bot - Docker Container Launcher"

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  🐳 CTI CHAT BOT -- DOCKER CONTAINER LAUNCHER" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "Packaging and launching CTI Chat Bot as an isolated Docker container...`n" -ForegroundColor Yellow

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Check Docker
docker info 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker is not running. Please start Docker Desktop first."
    exit 1
}

Write-Host "[1/3] Stopping previous cti-chat-bot container..." -ForegroundColor Gray
docker stop cti-chat-bot 2>$null | Out-Null
docker rm cti-chat-bot 2>$null | Out-Null

Write-Host "[2/3] Building CTI Chat Bot Docker image (cti-chat-bot:latest)..." -ForegroundColor Yellow
docker build -t cti-chat-bot:latest .
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker build failed."
    exit 1
}

Write-Host "`n[3/3] Running CTI Chat Bot container..." -ForegroundColor Yellow
docker run -d `
    --name cti-chat-bot `
    --restart unless-stopped `
    -p 8503:8503 `
    -p 8005:8005 `
    --add-host=host.docker.internal:host-gateway `
    cti-chat-bot:latest

Write-Host "`n==============================================================================" -ForegroundColor Cyan
Write-Host "  ✅ CTI CHAT BOT DOCKER CONTAINER IS ONLINE!" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  • Chatbot UI:   http://localhost:8503" -ForegroundColor White
Write-Host "  • Backend API:  http://localhost:8005/docs" -ForegroundColor White
Write-Host "  • Target DB:    mongodb://host.docker.internal:27017" -ForegroundColor White
Write-Host "==============================================================================`n" -ForegroundColor Cyan

Start-Sleep -Seconds 3
Start-Process "http://localhost:8503"

Write-Host "Container logs preview:" -ForegroundColor Gray
docker logs --tail 20 cti-chat-bot
