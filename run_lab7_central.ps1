# CTI Fusion Center - Launch Central Lab 7 Console
$ErrorActionPreference = "Stop"
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  STARTING LAB 7 (CTI FUSION CENTER) WITH CONNECTED EXPERIMENTS 8 TO 18" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "Dashboard will open at http://localhost:8501" -ForegroundColor Yellow

$pythonExe = "C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\CTI_Fusion_Center_Updated\.venv\Scripts\python.exe"
$scriptDir = "C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\CTI_Fusion_Center_Updated\CTI_Fusion_Center_Docker_Advanced_Checked\cti_fusion_center_docker_keyless"

Set-Location $scriptDir

if (Test-Path $pythonExe) {
    & $pythonExe -m streamlit run app.py
} else {
    streamlit run app.py
}
