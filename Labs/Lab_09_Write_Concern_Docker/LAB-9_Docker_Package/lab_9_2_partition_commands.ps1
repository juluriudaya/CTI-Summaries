# Lab 9.2 helper commands for Windows PowerShell.
# Run these on the Windows host, NOT inside lab9-runner.
# CAUTION: disconnecting a member temporarily interrupts replication. Do not
# disconnect the arbiter. Reconnect the same member when the test is complete.

Write-Host 'Current containers:'
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
Write-Host "`nCurrent Docker networks:"
docker network ls
Write-Host "`nReplica-set status:"
docker exec mongo-rs0-1 mongosh --quiet --eval "rs.status().members.forEach(m => print(m.name, m.stateStr, m.health))"
Write-Host "`nConfirm the actual Lab 8 network name using 'docker network ls'."
Write-Host "Then disconnect ONLY the secondary: docker network disconnect lab-8_default mongo-rs0-2"
Write-Host "Check status: docker exec mongo-rs0-1 mongosh --quiet --eval \"rs.status().members.forEach(m => print(m.name, m.stateStr, m.health))\""
Write-Host "Test w:1: docker exec mongo-rs0-1 mongosh --quiet --eval \"db.getSiblingDB('lab_9_2').partition_test.insertOne({test:'w1_during_partition',time:new Date()},{writeConcern:{w:1,wtimeout:5000}})\""
Write-Host "Test majority: docker exec mongo-rs0-1 mongosh --quiet --eval \"db.getSiblingDB('lab_9_2').partition_test.insertOne({test:'majority_during_partition',time:new Date()},{writeConcern:{w:'majority',wtimeout:5000}})\""
Write-Host "Reconnect after test: docker network connect lab-8_default mongo-rs0-2"
Write-Host "Verify recovery: docker exec mongo-rs0-1 mongosh --quiet --eval \"rs.status().members.forEach(m => print(m.name, m.stateStr, m.health))\""
