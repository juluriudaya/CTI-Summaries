from app.database import db, initialize_indexes
from app.security import hash_password

# Demo-only accounts. Change passwords before any non-local use.
DEMO_USERS = [
    {"username": "acme_admin", "password": "AdminPass123!", "user_id": "u-acme-admin", "tenant_id": "tenant-acme", "role": "admin"},
    {"username": "acme_user", "password": "UserPass123!", "user_id": "u-acme-user", "tenant_id": "tenant-acme", "role": "user"},
    {"username": "globex_admin", "password": "AdminPass123!", "user_id": "u-globex-admin", "tenant_id": "tenant-globex", "role": "admin"},
    {"username": "globex_user", "password": "UserPass123!", "user_id": "u-globex-user", "tenant_id": "tenant-globex", "role": "user"},
]

def main():
    initialize_indexes()
    for item in DEMO_USERS:
        db.users.update_one(
            {"username": item["username"], "tenant_id": item["tenant_id"]},
            {"$set": {
                "username": item["username"],
                "password_hash": hash_password(item["password"]),
                "user_id": item["user_id"],
                "tenant_id": item["tenant_id"],
                "role": item["role"],
            }},
            upsert=True,
        )
    print("Seeded 4 demo users.")
    print("Local demo usernames: acme_admin, acme_user, globex_admin, globex_user")
    print("Demo passwords are documented in README; do not reuse them elsewhere.")

if __name__ == "__main__":
    main()
