$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "=== Lab 12 integrated MongoDB security deployment ===" -ForegroundColor Cyan
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker CLI not found. Start Docker Desktop and verify: docker version"
}
docker version | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Docker Desktop is not available." }

# Ensure a private secrets folder exists; certgen writes the keyfile here.
New-Item -ItemType Directory -Force -Path ".\secrets" | Out-Null

# Compose starts a dedicated Lab 12 secured replica set.
# It does not stop, remove, or recreate any Lab 7-11 containers or volumes.
docker compose up -d certgen sec1 sec2 sec3
if ($LASTEXITCODE -ne 0) { throw "Could not start Lab 12 services." }

Write-Host "Waiting for Lab 12 nodes and running RBAC initialization..." -ForegroundColor Yellow
docker compose up --abort-on-container-exit --exit-code-from setup setup
if ($LASTEXITCODE -ne 0) {
    Write-Host "Setup container output:" -ForegroundColor Red
    docker logs lab12-setup
    throw "Lab 12 initialization did not complete. Inspect logs before retrying."
}

Write-Host "`nLab 12 replica set status:" -ForegroundColor Green
docker exec lab12-sec1 mongosh --quiet --tls --tlsCAFile /certs/ca.crt --tlsCertificateKeyFile /certs/client.pem --tlsAllowInvalidHostnames --eval "printjson(db.adminCommand({replSetGetStatus:1}).members.map(m=>({name:m.name,state:m.stateStr,health:m.health})))"
Write-Host "`nDeployment is running. Next run: .\Run-Experiments.ps1"
