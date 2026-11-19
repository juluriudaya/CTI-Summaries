# CTI Fusion Center - Master Experiments Runner PowerShell Script
param(
    [string]$Uri = "mongodb://localhost:27017"
)

$ErrorActionPreference = "Stop"
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  CTI FUSION CENTER -- MASTER EXPERIMENTS RUNNER (LABS 1 TO 18)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "Central Coordinator: Lab 7 (CTI Fusion Center)" -ForegroundColor Yellow
Write-Host "Connecting to URI:   $Uri" -ForegroundColor Yellow
Write-Host ""

$rootVenv = "C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\.venv\Scripts\python.exe"
$subVenv = "C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\CTI_Fusion_Center_Updated\.venv\Scripts\python.exe"
$scriptDir = "C:\Users\Julur\OneDrive\Desktop\NoSQL\LAB FROM-7\CTI_Fusion_Center_Updated\CTI_Fusion_Center_Docker_Advanced_Checked\cti_fusion_center_docker_keyless"

if (Test-Path $rootVenv) {
    $pythonExe = $rootVenv
} elseif (Test-Path $subVenv) {
    $pythonExe = $subVenv
} else {
    Write-Warning "Venv python not found, trying system python..."
    $pythonExe = "python"
}

& $pythonExe "$scriptDir\run_all_experiments.py" --uri $Uri
Write-Host ""
Write-Host "All experiments executed and verified." -ForegroundColor Green
