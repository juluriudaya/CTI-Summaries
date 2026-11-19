# Optional: attach a PREVIOUS LAB CONTAINER to Lab 12's bridge network.
# This script does not stop/recreate containers. It only connects a named
# container to lab12_security_net so it can reach sec1/sec2/sec3 by DNS.
param(
  [Parameter(Mandatory=$true)]
  [string]$ContainerName
)
$ErrorActionPreference = "Stop"
docker network inspect lab12_security_net *> $null
if ($LASTEXITCODE -ne 0) { throw "Start Lab 12 first: .\Run-Lab12.ps1" }
$networkJson = docker inspect --format '{{json .NetworkSettings.Networks}}' $ContainerName
if ($LASTEXITCODE -ne 0) { throw "Container '$ContainerName' was not found. Check docker ps -a." }
$containerNetworks = $networkJson | ConvertFrom-Json
if ($containerNetworks.PSObject.Properties.Name -contains "lab12_security_net") {
  Write-Host "$ContainerName is already connected to lab12_security_net. No changes were made." -ForegroundColor Yellow
  exit 0
}
docker network connect lab12_security_net $ContainerName
if ($LASTEXITCODE -ne 0) { throw "Could not connect '$ContainerName' to lab12_security_net." }
Write-Host "Connected $ContainerName to lab12_security_net. No container was restarted." -ForegroundColor Green
