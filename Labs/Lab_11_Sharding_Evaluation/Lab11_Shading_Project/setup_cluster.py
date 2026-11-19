"""
Initialize Lab 11 config-server replica set, two shard replica sets, then register shards.
Run from PowerShell: python setup_cluster.py
"""
import subprocess
import time

NODES = {
    "lab11-cfg1": 27019, "lab11-cfg2": 27019, "lab11-cfg3": 27019,
    "lab11-s1a": 27018, "lab11-s1b": 27018, "lab11-s1c": 27018,
    "lab11-s2a": 27018, "lab11-s2b": 27018, "lab11-s2c": 27018,
    "lab11-mongos": 27017,
}

def run(args, check=True):
    print("+", " ".join(args))
    subprocess.run(args, check=check, text=True)

def mongo_eval(container, port, js):
    run(["docker", "exec", container, "mongosh", "--quiet", "--port", str(port), "--eval", js])

def wait_node(container, port, timeout=120):
    print(f"Waiting for {container} on port {port} ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            ["docker", "exec", container, "mongosh", "--quiet", "--port", str(port),
             "--eval", "db.adminCommand({ping:1}).ok"],
            capture_output=True, text=True
        )
        if result.returncode == 0 and "1" in result.stdout:
            print(f"  READY: {container}")
            return
        time.sleep(2)
    raise RuntimeError(f"{container} did not become ready on port {port}. Check: docker logs {container}")

def initiate(container, port, config):
    js = f"""
    try {{
      const s = rs.status();
      if (s.ok === 1) print("Replica set already initialized");
    }} catch (e) {{
      print("Initiating replica set...");
      printjson(rs.initiate({config}));
    }}
    """
    mongo_eval(container, port, js)

def main():
    # Verify all nodes are running before configuring replica sets.
    for name, port in NODES.items():
        wait_node(name, port)

    initiate("lab11-cfg1", 27019,
        "{_id:'cfgrs',configsvr:true,members:[{_id:0,host:'lab11-cfg1:27019'},{_id:1,host:'lab11-cfg2:27019'},{_id:2,host:'lab11-cfg3:27019'}]}")
    initiate("lab11-s1a", 27018,
        "{_id:'shard1rs',members:[{_id:0,host:'lab11-s1a:27018',priority:2},{_id:1,host:'lab11-s1b:27018',priority:1},{_id:2,host:'lab11-s1c:27018',priority:0}]}")
    initiate("lab11-s2a", 27018,
        "{_id:'shard2rs',members:[{_id:0,host:'lab11-s2a:27018',priority:2},{_id:1,host:'lab11-s2b:27018',priority:1},{_id:2,host:'lab11-s2c:27018',priority:0}]}")

    print("Waiting 15 seconds for replica-set elections...")
    time.sleep(15)

    mongo_eval("lab11-mongos", 27017,
        "printjson(sh.addShard('shard1rs/lab11-s1a:27018,lab11-s1b:27018,lab11-s1c:27018'));")
    mongo_eval("lab11-mongos", 27017,
        "printjson(sh.addShard('shard2rs/lab11-s2a:27018,lab11-s2b:27018,lab11-s2c:27018'));")
    mongo_eval("lab11-mongos", 27017,
        "try { sh.enableSharding('cti_shard'); } catch(e) { print(e); } printjson(sh.status());")

    print("\nLab 11 cluster initialized.")
    print("Router URI: mongodb://localhost:27317")
    print("Next: verify with docker exec lab11-mongos mongosh --quiet --eval \"sh.status()\"")

if __name__ == "__main__":
    main()
