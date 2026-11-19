# PowerShell Master Launcher for CTI Fusion Center & CTI-AI Suite
$Host.UI.RawUI.WindowTitle = "CTI Fusion Center - Complete Enterprise System Suite"

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  🛡️  CTI FUSION CENTER & CTI-AI SUITE -- MASTER UNIFIED LAUNCHER" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "Central Hub: Labs 1 to 18 + Autonomous CTI-AI Chatbot & Mitigation Engine`n" -ForegroundColor Yellow

$rootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPython = Join-Path $rootDir ".venv\Scripts\python.exe"
$dashboardDir = Join-Path $rootDir "CTI_Fusion_Center_Updated\CTI_Fusion_Center_Docker_Advanced_Checked\cti_fusion_center_docker_keyless"
$chatDir = Join-Path $rootDir "LLM_Threat_Chat_App"

if (-not (Test-Path $venvPython)) {
    Write-Warning "Virtual environment python not found at: $venvPython"
    $venvPython = "python"
}

# 1. FastAPI Backend (8005)
Write-Host "[1/3] Checking CTI-AI Backend on port 8005..." -ForegroundColor Gray
$backendPort = Get-NetTCPConnection -LocalPort 8005 -State Listen -ErrorAction SilentlyContinue
if ($backendPort) {
    Write-Host "      [ACTIVE] FastAPI CTI-AI Backend is already running on port 8005." -ForegroundColor Green
} else {
    Write-Host "      [STARTING] Launching FastAPI CTI-AI Backend on port 8005..." -ForegroundColor Yellow
    Start-Process -FilePath $venvPython -ArgumentList "-m uvicorn main:app --host 0.0.0.0 --port 8005" -WorkingDirectory (Join-Path $chatDir "backend") -WindowStyle Minimized
    Start-Sleep -Seconds 2
}

# 2. Streamlit Dashboard (8502)
Write-Host "`n[2/3] Checking CTI SUMMARIES Dashboard on port 8502..." -ForegroundColor Gray
$dashPort = Get-NetTCPConnection -LocalPort 8502 -State Listen -ErrorAction SilentlyContinue
if ($dashPort) {
    Write-Host "      [ACTIVE] Streamlit Dashboard is already running on port 8502." -ForegroundColor Green
} else {
    Write-Host "      [STARTING] Launching CTI SUMMARIES Dashboard on port 8502..." -ForegroundColor Yellow
    Start-Process -FilePath $venvPython -ArgumentList "-m streamlit run app.py --server.port 8502 --server.headless true --browser.gatherUsageStats false" -WorkingDirectory $dashboardDir -WindowStyle Minimized
    Start-Sleep -Seconds 2
}

# 3. Streamlit Chat (8503)
Write-Host "`n[3/3] Checking CTI - AI Chat Console on port 8503..." -ForegroundColor Gray
$chatPort = Get-NetTCPConnection -LocalPort 8503 -State Listen -ErrorAction SilentlyContinue
if ($chatPort) {
    Write-Host "      [ACTIVE] Streamlit Chat Interface is already running on port 8503." -ForegroundColor Green
} else {
    Write-Host "      [STARTING] Launching CTI - AI Chat Console on port 8503..." -ForegroundColor Yellow
    Start-Process -FilePath $venvPython -ArgumentList "-m streamlit run chat_app.py --server.port 8503 --server.headless true --browser.gatherUsageStats false" -WorkingDirectory (Join-Path $chatDir "frontend") -WindowStyle Minimized
    Start-Sleep -Seconds 2
}

Write-Host "`n==============================================================================" -ForegroundColor Cyan
Write-Host "  ALL SERVICES SYNCHRONIZED AND ONLINE" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  * CTI SUMMARIES Dashboard:       http://localhost:8502" -ForegroundColor White
Write-Host "  * CTI - AI Threat & Lab Chat:    http://localhost:8503" -ForegroundColor White
Write-Host "  * FastAPI OpenAPI Documentation: http://localhost:8005/docs" -ForegroundColor White
Write-Host "==============================================================================`n" -ForegroundColor Cyan

Start-Process "http://localhost:8502"
Start-Process "http://localhost:8503"
