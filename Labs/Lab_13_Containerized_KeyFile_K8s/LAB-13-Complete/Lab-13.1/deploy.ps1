$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $root ".env"
if (!(Test-Path $envFile)) { throw "Copy .env.example to .env in the package root and set a strong password." }

$lines = Get-Content $envFile
$pwLine = $lines | Where-Object { $_ -match '^MONGO_ADMIN_PASSWORD=' } | Select-Object -First 1
$userLine = $lines | Where-Object { $_ -match '^MONGO_ADMIN_USERNAME=' } | Select-Object -First 1
if (!$pwLine) { throw "MONGO_ADMIN_PASSWORD is missing from .env." }
$pw = ($pwLine -split '=',2)[1].Trim()
$user = if ($userLine) { ($userLine -split '=',2)[1].Trim() } else { "admin" }
if ($pw.Length -lt 20 -or $pw -match '[^A-Za-z0-9]' -or $pw -match 'ReplaceThis') { throw "Set a unique password of at least 20 alphanumeric characters in .env." }

Push-Location $PSScriptRoot
try {
  docker compose --env-file $envFile -p lab13 config --quiet
  if ($LASTEXITCODE -ne 0) { throw "Compose validation failed." }
  docker compose --env-file $envFile -p lab13 up -d mongo1 mongo2 mongo3
  if ($LASTEXITCODE -ne 0) { throw "MongoDB containers failed to start." }
  Start-Sleep -Seconds 15

  $init = @'
try { rs.status(); print("Already initialized"); }
catch(e) {
  rs.initiate({_id:"rs0",members:[
    {_id:0,host:"mongo1:27017",priority:2},
    {_id:1,host:"mongo2:27017",priority:1},
    {_id:2,host:"mongo3:27017",priority:1}
  ]});
}
'@
  $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($init))
  docker exec lab13-mongo-1 mongosh --quiet --eval "eval(Buffer.from('$b64','base64').toString())"
  if ($LASTEXITCODE -ne 0) { throw "Replica-set initiation failed. Inspect docker logs lab13-mongo-1." }

  $primary = $false
  for ($i=0; $i -lt 60; $i++) {
    $r = docker exec lab13-mongo-1 mongosh --quiet --eval "db.hello().isWritablePrimary" 2>$null
    if (($r | Out-String).Trim() -eq "true") { $primary=$true; break }
    Start-Sleep -Seconds 2
  }
  if (!$primary) { throw "mongo1 did not become primary. Check container logs and replica status." }

  $uJson = ConvertTo-Json -Compress $user
  $pJson = ConvertTo-Json -Compress $pw
  $js = "db.getSiblingDB('admin').createUser({user:$uJson,pwd:$pJson,roles:[{role:'root',db:'admin'}]})"
  $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($js))
  docker exec lab13-mongo-1 mongosh --quiet --eval "try { eval(Buffer.from('$b64','base64').toString()); } catch(e) { if(e.codeName==='DuplicateKey' || e.code===51003) print('Admin already exists'); else throw e; }"
  if ($LASTEXITCODE -ne 0) { throw "Admin creation/check failed. Inspect existing users if this is a rerun." }

  Write-Host "Lab 13.1 deployment complete. Replica set: rs0. Ports: 27217, 27218, 27219."
  Write-Host "Verify: docker exec -it lab13-mongo-1 mongosh -u $user -p --authenticationDatabase admin"
}
finally { Pop-Location }
