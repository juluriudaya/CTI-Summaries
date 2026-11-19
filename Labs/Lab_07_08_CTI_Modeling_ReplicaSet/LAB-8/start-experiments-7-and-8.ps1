$ErrorActionPreference = "Stop"
$ctiPath = $env:CTI_PROJECT_PATH
if ([string]::IsNullOrWhiteSpace($ctiPath)) {
  $ctiPath = "C:\\Users\\Julur\\OneDrive\\Desktop\\CTI_Fusion_Center_Docker_Advanced_Checked\\cti_fusion_center_docker_keyless"
}
if (-not (Test-Path (Join-Path $ctiPath "docker-compose.yml"))) {
  throw "Experiment 7 docker-compose.yml not found at '$ctiPath'. Set CTI_PROJECT_PATH to your Experiment 7 folder."
}
Write-Host "Starting Experiment 7: CTI Fusion Center..."
docker compose -f (Join-Path $ctiPath "docker-compose.yml") --project-directory $ctiPath up -d --build
if ($LASTEXITCODE -ne 0) { throw "Experiment 7 failed to start." }
Write-Host "Starting Experiment 8: MongoDB replica set + observer..."
docker compose -f (Join-Path $PSScriptRoot "docker-compose-replicaset.yml") --project-directory $PSScriptRoot up -d --build
if ($LASTEXITCODE -ne 0) { throw "Experiment 8 failed to start." }
Write-Host "Initializing Experiment 8 replica set..."
& (Join-Path $PSScriptRoot "initialize-replica-set.ps1")
Write-Host "Both experiments started. CTI dashboard: http://localhost:8501"
Write-Host "Experiment 8 MongoDB host ports: 27117, 27118, 27119"
