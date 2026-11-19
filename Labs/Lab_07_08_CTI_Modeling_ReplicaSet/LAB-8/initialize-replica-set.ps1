$ErrorActionPreference = "Stop"
Write-Host "Waiting for MongoDB node 1..."
for ($i=0; $i -lt 30; $i++) {
  docker exec mongo-rs0-1 mongosh --quiet --eval "db.adminCommand('ping').ok" 2>$null | Out-Null
  if ($LASTEXITCODE -eq 0) { break }
  Start-Sleep -Seconds 2
}
Write-Host "Initializing replica set rs0 (2 data-bearing nodes + 1 arbiter)..."
$js = @'
try {
  rs.status();
  print("Replica set already initialized.");
} catch (e) {
  rs.initiate({
    _id: "rs0",
    members: [
      { _id: 0, host: "host.docker.internal:27117", priority: 2 },
      { _id: 1, host: "host.docker.internal:27118", priority: 1 },
      { _id: 2, host: "host.docker.internal:27119", arbiterOnly: true, priority: 0 }
    ]
  });
}
'@
docker exec mongo-rs0-1 mongosh --quiet --eval $js
if ($LASTEXITCODE -ne 0) { throw "Replica-set initialization command failed." }
Start-Sleep -Seconds 10
Write-Host "Replica set status:"
docker exec mongo-rs0-1 mongosh --quiet --eval "rs.status().members.forEach(m => print(m.name, m.stateStr, 'health='+m.health))"
