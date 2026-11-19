
import os
import time

from pymongo import MongoClient
from pymongo.errors import OperationFailure


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

URI = os.environ["MONGO_URI"]
ADMIN = os.getenv("ADMIN_USER", "lab12_admin")
PASSWORD = os.environ["ADMIN_PASSWORD"]

# Connect directly to sec1 before using the replica-set URI.
DIRECT_URI = "mongodb://sec1:27017/?directConnection=true"


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def connect(uri=URI, user=None, password=None, auth_source="admin"):

    kwargs = {
        "serverSelectionTimeoutMS": 10000,
        "connectTimeoutMS": 10000,
        "tls": True,
        "tlsCAFile": "/certs/ca.crt",
        "tlsCertificateKeyFile": "/certs/client.pem",
        "tlsAllowInvalidHostnames": True
    }

    if user:
        kwargs.update(
            username=user,
            password=password,
            authSource=auth_source
        )

    return MongoClient(uri, **kwargs)


# --------------------------------------------------
# WAIT FOR MONGODB
# --------------------------------------------------

def wait_for_server():

    print("[INFO] Waiting for MongoDB sec1...")

    for attempt in range(60):

        try:
            c = connect(
                DIRECT_URI,
                user=ADMIN,
                password=PASSWORD
            )

            c.admin.command("ping")
            c.close()

            print("[OK] MongoDB sec1 is reachable over TLS.")
            return

        except Exception as e:

            print(
                f"[INFO] MongoDB connection attempt "
                f"{attempt + 1}/60: {e}"
            )

            time.sleep(2)

    raise RuntimeError(
        "MongoDB sec1 did not become reachable over TLS."
    )


# --------------------------------------------------
# REPLICA SET INITIALIZATION / VERIFICATION
# --------------------------------------------------

def initiate():

    print("[INFO] Checking replica set...")

    c = connect(
        DIRECT_URI,
        user=ADMIN,
        password=PASSWORD
    )

    try:

        try:
            status = c.admin.command("replSetGetStatus")

            print("[OK] Replica set already initialized.")
            return

        except OperationFailure as e:

            if e.code != 94:
                raise

            print("[INFO] Replica set is not initialized.")

        cfg = {
            "_id": "secrs",
            "members": [
                {
                    "_id": 0,
                    "host": "sec1:27017",
                    "priority": 2
                },
                {
                    "_id": 1,
                    "host": "sec2:27017",
                    "priority": 1
                },
                {
                    "_id": 2,
                    "host": "sec3:27017",
                    "priority": 1
                }
            ]
        }

        c.admin.command("replSetInitiate", cfg)

        print("[OK] Replica set initialization requested.")

    finally:
        c.close()


# --------------------------------------------------
# WAIT FOR PRIMARY
# --------------------------------------------------

def wait_primary():

    print("[INFO] Waiting for PRIMARY election...")

    for attempt in range(90):

        c = None

        try:

            c = connect(
                user=ADMIN,
                password=PASSWORD
            )

            hello = c.admin.command("hello")

            if hello.get("isWritablePrimary"):

                print("[OK] PRIMARY elected successfully.")
                return

        except Exception as e:

            if attempt % 10 == 0:
                print(f"[INFO] Waiting for primary: {e}")

        finally:

            if c is not None:
                c.close()

        time.sleep(2)

    raise RuntimeError("No writable PRIMARY elected.")


# --------------------------------------------------
# VERIFY ADMINISTRATOR
# --------------------------------------------------

def verify_admin():

    print("[INFO] Verifying administrator account...")

    c = connect(
        DIRECT_URI,
        user=ADMIN,
        password=PASSWORD
    )

    try:

        result = c.admin.command("ping")

        if result.get("ok") != 1:
            raise RuntimeError("Administrator authentication failed.")

        print("[OK] Administrator authentication successful.")

    finally:
        c.close()


# --------------------------------------------------
# AUTHENTICATED CLIENT
# --------------------------------------------------

def authenticated_client(user=ADMIN, password=PASSWORD):

    return connect(
        user=user,
        password=password
    )


# --------------------------------------------------
# CREATE CUSTOM RBAC ROLES AND USERS
# --------------------------------------------------

def create_rbac(db):

    print("[INFO] Creating RBAC roles...")

    role_defs = [

        (
            "threatReader",
            [
                {
                    "resource": {
                        "db": "cti_intel",
                        "collection": "threats"
                    },
                    "actions": ["find"]
                },
                {
                    "resource": {
                        "db": "cti_intel",
                        "collection": "sightings"
                    },
                    "actions": ["find"]
                }
            ]
        ),

        (
            "sightingsWriter",
            [
                {
                    "resource": {
                        "db": "cti_intel",
                        "collection": "sightings"
                    },
                    "actions": [
                        "find",
                        "insert",
                        "update",
                        "remove"
                    ]
                }
            ]
        ),

        (
            "publicSourcesReader",
            [
                {
                    "resource": {
                        "db": "cti_intel",
                        "collection": "sources_public"
                    },
                    "actions": ["find"]
                }
            ]
        ),

        (
            "sourcesFullReader",
            [
                {
                    "resource": {
                        "db": "cti_intel",
                        "collection": "sources"
                    },
                    "actions": ["find"]
                }
            ]
        )

    ]

    for name, privileges in role_defs:

        try:

            db.command(
                "createRole",
                name,
                privileges=privileges,
                roles=[]
            )

            print(f"[OK] Created role: {name}")

        except OperationFailure as e:

            if e.code == 51002:

                db.command(
                    "updateRole",
                    name,
                    privileges=privileges,
                    roles=[]
                )

                print(f"[OK] Updated role: {name}")

            else:
                raise

    # Application users

    users = [

        (
            "app_user_read",
            "ReadOnly_Lab12_ChangeMe!",
            [
                {
                    "role": "threatReader",
                    "db": "admin"
                }
            ]
        ),

        (
            "app_user_write",
            "WriteOnly_Lab12_ChangeMe!",
            [
                {
                    "role": "sightingsWriter",
                    "db": "admin"
                }
            ]
        ),

        (
            "viewer_user",
            "Viewer_Lab12_ChangeMe!",
            [
                {
                    "role": "publicSourcesReader",
                    "db": "admin"
                }
            ]
        ),

        (
            "analyst_lead",
            "Analyst_Lab12_ChangeMe!",
            [
                {
                    "role": "sourcesFullReader",
                    "db": "admin"
                },
                {
                    "role": "publicSourcesReader",
                    "db": "admin"
                }
            ]
        )

    ]

    for name, pwd, roles in users:

        try:

            db.command(
                "createUser",
                name,
                pwd=pwd,
                roles=roles
            )

            print(f"[OK] Created user: {name}")

        except OperationFailure as e:

            if e.code == 51003:

                db.command(
                    "updateUser",
                    name,
                    pwd=pwd,
                    roles=roles
                )

                print(f"[OK] Updated existing user: {name}")

            else:
                raise


# --------------------------------------------------
# CREATE DEMONSTRATION DATA AND REDACTED VIEW
# --------------------------------------------------

def seed_data(db):

    print("[INFO] Preparing demonstration data...")

    src = db["sources"]

    if src.count_documents({}) == 0:

        src.insert_many([
            {
                "name": "CISA KEV",
                "type": "government",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "reliability": 0.99
            },
            {
                "name": "NVD",
                "type": "database",
                "url": "https://nvd.nist.gov/",
                "reliability": 0.95
            }
        ])

    threats = db["threats"]

    if threats.count_documents({}) == 0:

        threats.insert_many([
            {
                "_id": "CVE-2024-0001",
                "name": "Lab demonstration vulnerability",
                "severity": "high"
            },
            {
                "_id": "CVE-2024-0002",
                "name": "Second lab demonstration vulnerability",
                "severity": "medium"
            }
        ])

    sightings = db["sightings"]

    if sightings.count_documents({}) == 0:

        sightings.insert_one({
            "threat_id": "CVE-2024-0001",
            "source": "lab-seed",
            "status": "new"
        })

    # Create public view without reliability field.

    try:
        db.command("drop", "sources_public")

    except OperationFailure as e:

        if e.code != 26:
            raise

    db.command(
        "create",
        "sources_public",
        viewOn="sources",
        pipeline=[
            {
                "$project": {
                    "name": 1,
                    "type": 1,
                    "url": 1
                }
            }
        ]
    )

    print("[OK] Demo data and redacted view created.")


# --------------------------------------------------
# OPTIONAL LAB 7 DATA IMPORT
# --------------------------------------------------

def import_lab7_if_configured(db):

    source_uri = os.getenv(
        "LAB7_MONGODB_URI",
        ""
    ).strip()

    if not source_uri:

        print(
            "[INFO] LAB7_MONGODB_URI not set. "
            "Using demonstration data."
        )

        return

    source_db = os.getenv(
        "LAB7_DATABASE",
        "cti_cisa_kev"
    )

    source_col = os.getenv(
        "LAB7_COLLECTION",
        "indicators"
    )

    print(
        f"[INFO] Importing Lab 7 data from "
        f"{source_db}.{source_col}"
    )

    src_client = MongoClient(
        source_uri,
        serverSelectionTimeoutMS=5000
    )

    try:

        source = src_client[source_db][source_col]

        target = db["lab7_indicators"]

        if target.count_documents({}) == 0:

            batch = []
            total = 0

            for doc in source.find({}).batch_size(500):

                doc.pop("_id", None)
                batch.append(doc)

                if len(batch) >= 500:

                    target.insert_many(
                        batch,
                        ordered=False
                    )

                    total += len(batch)
                    batch = []

            if batch:

                target.insert_many(
                    batch,
                    ordered=False
                )

                total += len(batch)

            print(
                f"[OK] Imported {total} Lab 7 documents."
            )

        else:

            print("[INFO] Lab 7 data already imported. Skipping.")

    finally:

        src_client.close()


# --------------------------------------------------
# MAIN EXECUTION
# --------------------------------------------------

def main():

    print("=" * 55)
    print("LAB 12: SECURE MONGODB REPLICA SET")
    print("=" * 55)

    # Step 1: Check connection
    wait_for_server()

    # Step 2: Verify replica set
    initiate()

    # Step 3: Wait for primary
    wait_primary()

    # Step 4: Verify existing administrator
    verify_admin()

    # Step 5: Connect using administrator credentials
    c = authenticated_client()

    try:

        hello = c.admin.command("hello")

        print(
            "[OK] Authenticated connection:",
            hello.get("setName")
        )

        db = c["cti_intel"]

        # Step 6: Create demonstration data
        seed_data(db)

        # Step 7: Optional Lab 7 import
        import_lab7_if_configured(db)

        # Step 8: Create RBAC roles and users
        create_rbac(c["admin"])

        print("=" * 55)
        print("[SUCCESS] LAB 12.1 SETUP COMPLETE")
        print("=" * 55)

    finally:

        c.close()


if __name__ == "__main__":

    main()
