# Experiments 7 + 8 combined startup

This bundle keeps Experiment 7's existing project folder and data intact and adds Experiment 8's replica set on separate host ports.

## Start both on Windows PowerShell

1. Extract this LAB-8 folder somewhere convenient.
2. Make sure Experiment 7 still exists at `C:\Users\Julur\OneDrive\Desktop\CTI_Fusion_Center_Docker_Advanced_Checked\cti_fusion_center_docker_keyless`. If not, set `$env:CTI_PROJECT_PATH` to its actual path.
3. Open PowerShell in this folder and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\start-experiments-7-and-8.ps1
```

The script starts Experiment 7 first, then Experiment 8, then initializes replica set `rs0`. It does not remove volumes or run `down -v`. Experiment 7 remains at http://localhost:8501. Experiment 8 uses host ports 27117, 27118, and 27119 to avoid the common 27017-27019 conflicts.

## Verify

```powershell
docker compose -f .\docker-compose-replicaset.yml ps
docker exec mongo-rs0-1 mongosh --quiet --eval "rs.status().members.forEach(m => print(m.name, m.stateStr, m.health))"
docker compose -f .\docker-compose-replicaset.yml logs --tail=50 observer
```

## Insert and verify replication

```powershell
docker exec mongo-rs0-1 mongosh --quiet --eval "db.getSiblingDB('lab8_demo').replication.insertOne({message:'Experiment 8 replication check',createdAt:new Date()})"
docker exec mongo-rs0-2 mongosh --quiet --eval "db.getSiblingDB('lab8_demo').replication.find().toArray()"
```

The arbiter does not store application data, so verify replicated documents on node 2, not node 3.

## Force failover

```powershell
docker exec mongo-rs0-1 mongosh --quiet --eval "rs.stepDown(60)"
docker exec mongo-rs0-2 mongosh --quiet --eval "rs.status().members.forEach(m => print(m.name, m.stateStr, m.health))"
```

## Docker Hub

The observer image is configured as `udayajuluri/mongodb-replica-observer:latest`. Build and push it from this folder:

```powershell
docker login
docker compose -f .\docker-compose-replicaset.yml build observer
docker push udayajuluri/mongodb-replica-observer:latest
```

The three MongoDB nodes use the official `mongo:7` image. Do not upload database files/volumes to Docker Hub.

## Notes

- Do not run `docker compose down -v`; it removes named data volumes.
- This observer continuously logs the current primary and changes after election.
- MongoDB replica set members use `host.docker.internal` advertised endpoints to match this Windows-host lab setup.
