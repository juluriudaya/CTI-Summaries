$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
try {
  kubectl cluster-info | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "kubectl cannot reach a cluster. Enable Kubernetes or start kind/minikube." }

  $key = Join-Path $PSScriptRoot "k8s\keyfile"
  if (!(Test-Path $key)) {
    Write-Host "Generating KeyFile with Docker..."
    $out = docker run --rm alpine:3.20 sh -c "apk add --no-cache openssl >/dev/null && openssl rand -base64 756"
    if ($LASTEXITCODE -ne 0 -or !$out) { throw "KeyFile generation failed. Is Docker running?" }
    [IO.File]::WriteAllText($key, (($out | Out-String).Trim() + "`n"), [Text.Encoding]::ASCII)
  }

  kubectl apply -f .\k8s\namespace.yaml
  if ($LASTEXITCODE -ne 0) { throw "Namespace apply failed." }
  kubectl -n nosql-labs create secret generic mongo-keyfile --from-file=keyfile=$key --dry-run=client -o yaml | kubectl apply -f -
  if ($LASTEXITCODE -ne 0) { throw "KeyFile Secret creation failed." }
  kubectl apply -f .\k8s\mongo-headless-svc.yaml
  if ($LASTEXITCODE -ne 0) { throw "Service apply failed." }
  kubectl apply -f .\k8s\mongo-statefulset.yaml
  if ($LASTEXITCODE -ne 0) { throw "StatefulSet apply failed." }
  kubectl rollout status statefulset/mongo -n nosql-labs --timeout=300s
  if ($LASTEXITCODE -ne 0) { throw "StatefulSet not ready. Inspect kubectl get pods and describe pod." }

  $init = @'
try { rs.status(); print("Already initialized"); }
catch(e) {
  rs.initiate({_id:"rs0",members:[
    {_id:0,host:"mongo-0.mongo-headless-svc.nosql-labs.svc.cluster.local:27017",priority:2},
    {_id:1,host:"mongo-1.mongo-headless-svc.nosql-labs.svc.cluster.local:27017",priority:1},
    {_id:2,host:"mongo-2.mongo-headless-svc.nosql-labs.svc.cluster.local:27017",priority:1}
  ]});
}
'@
  $tmpName = "lab13-init-replica.js"
  $tmp = Join-Path $PSScriptRoot $tmpName
  try {
    [IO.File]::WriteAllText($tmp, $init, [Text.Encoding]::UTF8)
    kubectl cp ".\$tmpName" nosql-labs/mongo-0:/tmp/init-replica.js
    if ($LASTEXITCODE -ne 0) { throw "Could not copy replica initialization script." }
  }
  finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
  }
  kubectl exec -n nosql-labs mongo-0 -- mongosh --quiet /tmp/init-replica.js
  if ($LASTEXITCODE -ne 0) { throw "Replica-set initialization failed." }

  $envFile = Join-Path (Split-Path -Parent $PSScriptRoot) ".env"
  $lines = Get-Content $envFile
  $pwLine = $lines | Where-Object { $_ -match '^MONGO_ADMIN_PASSWORD=' } | Select-Object -First 1
  $userLine = $lines | Where-Object { $_ -match '^MONGO_ADMIN_USERNAME=' } | Select-Object -First 1
  if (!$pwLine) { throw "Set MONGO_ADMIN_PASSWORD in package-root .env." }
  $pw = ($pwLine -split '=',2)[1].Trim()
  $user = if ($userLine) { ($userLine -split '=',2)[1].Trim() } else { "admin" }
  if ($pw.Length -lt 20 -or $pw -match '[^A-Za-z0-9]' -or $pw -match 'ReplaceThis') { throw "Use a 20+ character alphanumeric password in .env." }
  $uJson = ConvertTo-Json -Compress $user
  $pJson = ConvertTo-Json -Compress $pw
  $js = "try { db.getSiblingDB('admin').createUser({user:$uJson,pwd:$pJson,roles:[{role:'root',db:'admin'}]}); } catch(e) { if(e.codeName==='DuplicateKey' || e.code===51003) print('Admin already exists'); else throw e; }"
  $jsB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($js))
  kubectl exec -n nosql-labs mongo-0 -- mongosh --quiet --eval "eval(Buffer.from('$jsB64','base64').toString())"
  if ($LASTEXITCODE -ne 0) { throw "Admin creation/check failed." }
  kubectl get pods,pvc,svc -n nosql-labs
}
finally { Pop-Location }
