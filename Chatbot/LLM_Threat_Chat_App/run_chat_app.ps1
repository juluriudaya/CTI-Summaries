# PowerShell Launcher for CTI LLM Chat Application
Write-Host "=======================================================================" -ForegroundColor Cyan
Write-Host "  CTI-AI -- LLM/SLM THREAT CHAT & AUTONOMOUS MITIGATOR" -ForegroundColor Cyan
Write-Host "=======================================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$venvPython = Join-Path (Split-Path -Parent $scriptDir) ".venv\Scripts\python.exe"

Write-Host "`n[1/2] Starting FastAPI Backend on port 8005..." -ForegroundColor Yellow
Start-Process $venvPython -ArgumentList "-m uvicorn backend.main:app --host 0.0.0.0 --port 8005" -WindowStyle Normal

Start-Sleep -Seconds 3

Write-Host "[2/2] Starting Streamlit Chat Frontend on port 8503..." -ForegroundColor Green
Start-Process $venvPython -ArgumentList "-m streamlit run frontend\chat_app.py --server.port 8503 --server.address 0.0.0.0" -WindowStyle Normal

Write-Host "`nDeployment Complete!" -ForegroundColor Cyan
Write-Host "  * Backend API Swagger: http://localhost:8005/docs" -ForegroundColor White
Write-Host "  * Chat Interface:      http://localhost:8503" -ForegroundColor White
