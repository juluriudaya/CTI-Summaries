# CTI Chat Bot - Deep Model Training Pipeline
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  🚀 CTI CHAT BOT: DEEP MODEL TRAINING & RE-INDEXING PIPELINE" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "Training character and word n-gram vector models across all 18 labs,"
Write-Host "57 viva defense questions, and cyber threat intelligence signatures...`n"

$rootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonPath = Join-Path $rootDir ".venv\Scripts\python.exe"

if (-not (Test-Path $pythonPath)) {
    $pythonPath = "python"
}

$scriptPath = Join-Path $rootDir "LLM_Threat_Chat_App\backend\train_model.py"
& $pythonPath $scriptPath

Write-Host "`n[+] Model weights saved to: LLM_Threat_Chat_App\backend\trained_model_weights.joblib" -ForegroundColor Green
