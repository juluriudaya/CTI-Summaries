# CTI Fusion Center - Centralized Dashboard Launcher
$ErrorActionPreference = "Stop"
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  CTI FUSION CENTER — CENTRALIZED LABS DASHBOARD (LABS 7 TO 18)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

$portActive = Get-NetTCPConnection -LocalPort 8502 -State Listen -ErrorAction SilentlyContinue
if ($portActive) {
    Write-Host "[OK] Dashboard server is already active on port 8502." -ForegroundColor Green
    Write-Host "Opening browser at http://localhost:8502 ..." -ForegroundColor Yellow
    Start-Process "http://localhost:8502"
    exit 0
}

Write-Host "Starting Streamlit server on http://localhost:8502 ..." -ForegroundColor Yellow
Start-Process "http://localhost:8502"

$rootVenv = "C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\.venv\Scripts\python.exe"
$subVenv = "C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\CTI_Fusion_Center_Updated\.venv\Scripts\python.exe"
$scriptDir = "C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\CTI_Fusion_Center_Updated\CTI_Fusion_Center_Docker_Advanced_Checked\cti_fusion_center_docker_keyless"

Set-Location $scriptDir

if (Test-Path $rootVenv) {
    Write-Host "Using Virtual Environment: $rootVenv" -ForegroundColor Green
    & $rootVenv -m streamlit run app.py --server.port 8502 --server.headless false
} elseif (Test-Path $subVenv) {
    Write-Host "Using Virtual Environment: $subVenv" -ForegroundColor Green
    & $subVenv -m streamlit run app.py --server.port 8502 --server.headless false
} else {
    streamlit run app.py --server.port 8502 --server.headless false
}
