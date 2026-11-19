$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($env:LAB12_ADMIN_PASSWORD)) { throw "Set LAB12_ADMIN_PASSWORD in this PowerShell session before running this script." }
docker run --rm --network lab12_security_net `
  -v "${PWD}\scripts:/work" -v "${PWD}\certs:/certs:ro" `
  -e ADMIN_USER=lab12_admin `
  -e ADMIN_PASSWORD="$env:LAB12_ADMIN_PASSWORD" `
  python:3.12-slim sh -c "pip install --quiet pymongo==4.10.1 && python /work/experiments.py"
if ($LASTEXITCODE -ne 0) { throw "Experiment script failed. Review the output above." }
