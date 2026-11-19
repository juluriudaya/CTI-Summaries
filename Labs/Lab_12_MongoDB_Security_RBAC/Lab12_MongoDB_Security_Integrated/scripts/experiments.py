import os, time, statistics, ssl
from pymongo import MongoClient, WriteConcern
from pymongo.errors import OperationFailure, PyMongoError, ServerSelectionTimeoutError

URI = os.getenv("MONGO_URI",
 "mongodb://sec1:27017,sec2:27017,sec3:27017/?replicaSet=secrs")
CA = "/certs/ca.crt"
CLIENT = "/certs/client.pem"
ADMIN = os.getenv("ADMIN_USER","lab12_admin")
ADMIN_PW = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PW:
    raise RuntimeError("Set ADMIN_PASSWORD before running the Lab 12 experiments.")

def client(user=None, password=None, tls=True, client_cert=True):
    kw = {"serverSelectionTimeoutMS":5000}
    if tls:
        kw.update(tls=True, tlsCAFile=CA, tlsAllowInvalidHostnames=True)
        if client_cert: kw["tlsCertificateKeyFile"] = CLIENT
    if user:
        kw.update(username=user,password=password,authSource="admin")
    return MongoClient(URI, **kw)

def expect_denied(fn, label):
    try:
        fn()
        print("[FAIL] Expected authorization denial:", label)
    except OperationFailure as e:
        if e.code == 13:
            print("[PASS] Correctly denied (code 13):", label)
        else:
            print("[WARN] Operation failed with another MongoDB error:", label, e)

def rbac():
    print("\n=== Lab 12.1: RBAC permission tests ===")
    ro=client("app_user_read","ReadOnly_Lab12_ChangeMe!")
    try:
        print("[PASS] app_user_read can read threats:", ro.cti_intel.threats.count_documents({}))
        expect_denied(lambda: ro.cti_intel.sightings.insert_one({"test":"forbidden"}),
                      "read-only user insert into sightings")
    finally: ro.close()

    wr=client("app_user_write","WriteOnly_Lab12_ChangeMe!")
    try:
        wr.cti_intel.sightings.insert_one({"test":"allowed","source":"lab12"})
        print("[PASS] app_user_write inserted into sightings")
        expect_denied(lambda: wr.cti_intel.threats.insert_one({"_id":"FORBIDDEN"}),
                      "writer insert into threats")
        expect_denied(lambda: wr.cti_intel.sources.find_one({}),
                      "writer read sources")
    finally: wr.close()

    viewer=client("viewer_user","Viewer_Lab12_ChangeMe!")
    try:
        docs=list(viewer.cti_intel.sources_public.find({},{"_id":0}))
        print("[PASS] viewer_user reads redacted view:", docs)
        expect_denied(lambda: viewer.cti_intel.sources.find_one({}),
                      "viewer access to base sources collection")
    finally: viewer.close()

    analyst=client("analyst_lead","Analyst_Lab12_ChangeMe!")
    try:
        print("[PASS] analyst_lead reads base source with reliability:",
              analyst.cti_intel.sources.find_one({},{"_id":0}))
    finally: analyst.close()

def field_redaction():
    print("\n=== Field-level redaction verification ===")
    c=client("viewer_user","Viewer_Lab12_ChangeMe!")
    try:
        d=c.cti_intel.sources_public.find_one({},{"_id":0})
        assert d is not None and "reliability" not in d
        print("[PASS] reliability field is absent from viewer output.")
    finally: c.close()

def transaction_rbac():
    print("\n=== Lab 10 connection: RBAC inside a transaction ===")
    c=client("app_user_write","WriteOnly_Lab12_ChangeMe!")
    try:
        db=c.cti_intel
        marker="lab12-rbac-transaction-test"
        try: db.sightings.delete_many({"marker":marker})
        except Exception: pass
        with c.start_session() as s:
            s.start_transaction()
            try:
                db.sightings.insert_one({"marker":marker,"step":"allowed"},session=s)
                db.threats.insert_one({"_id":"LAB12-FORBIDDEN-TX","marker":marker},session=s)
                s.commit_transaction()
                print("[FAIL] Forbidden transaction unexpectedly committed.")
            except OperationFailure as e:
                s.abort_transaction()
                print("[PASS] Forbidden operation aborted transaction:", e.code, e.details.get("codeName"))
        remaining=db.sightings.count_documents({"marker":marker})
        print("[VERIFY] Allowed insert remaining after abort:",remaining,"(expected 0)")
    finally: c.close()

def write_concern():
    print("\n=== Lab 9 connection: write concern test ===")
    c=client(ADMIN,ADMIN_PW)
    try:
        base=c.lab12_security.write_concern_test
        for w in (1,"majority"):
            col=base.with_options(write_concern=WriteConcern(w=w))
            start=time.perf_counter()
            for i in range(30):
                col.insert_one({"w":str(w),"i":i,"created":time.time()})
            elapsed=(time.perf_counter()-start)*1000
            print(f"[RESULT] w={w}: 30 inserts in {elapsed:.2f} ms")
    finally: c.close()

def tls_tests():
    print("\n=== Lab 12.2: TLS tests ===")
    # Plain TCP must fail because requireTLS is configured.
    try:
        p=MongoClient("mongodb://sec1:27017/?directConnection=true",
                      serverSelectionTimeoutMS=2500)
        p.admin.command("ping")
        print("[FAIL] Plain connection unexpectedly succeeded.")
        p.close()
    except Exception as e:
        print("[PASS] Plain connection rejected:",type(e).__name__)
    # Trusted CA + client cert + SCRAM credentials succeeds.
    c=client(ADMIN,ADMIN_PW)
    try:
        print("[PASS] TLS + client certificate + SCRAM:",c.admin.command("ping"))
    finally: c.close()
    # Wrong CA test is done by a separate caller/host test; don't fabricate result.
    print("[INFO] Wrong-CA rejection can be tested using an unrelated CA file.")

def failover():
    print("\n=== Lab 8 connection: authenticated TLS replica-set failover ===")
    c=client(ADMIN,ADMIN_PW)
    try:
        before=c.admin.command("hello").get("primary")
        print("[INFO] Primary before stepdown:",before)
        try:
            c.admin.command({"replSetStepDown":15,"force":True})
        except PyMongoError:
            pass
    finally: c.close()
    for _ in range(40):
        try:
            r=client("app_user_read","ReadOnly_Lab12_ChangeMe!")
            r.cti_intel.threats.find_one()
            after=r.admin.command("hello").get("primary")
            r.close()
            if after:
                print("[PASS] Read-only user recovered over TLS after election. New primary:",after)
                return
        except Exception: pass
        time.sleep(2)
    print("[WARN] Could not verify a new primary before timeout.")

def main():
    rbac()
    field_redaction()
    transaction_rbac()
    write_concern()
    tls_tests()
    failover()
    print("\n=== Lab 12 experiment run finished ===")

if __name__=="__main__": main()
