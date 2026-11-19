from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

atlas_uri = os.getenv("MONGO_URI_ATLAS")

atlas_client = MongoClient(atlas_uri)
docker_client = MongoClient("mongodb://localhost:27017")

atlas_client.admin.command("ping")
docker_client.admin.command("ping")

print("Both MongoDB connections are successful!\n")

atlas_info = atlas_client.server_info()
docker_info = docker_client.server_info()

atlas_version = atlas_info["version"]
docker_version = docker_info["version"]

print("MongoDB Server Version Comparison")
print("---------------------------------")
print("MongoDB Atlas Version :", atlas_version)
print("Docker MongoDB Version:", docker_version)

if atlas_version == docker_version:
    print("\nResult: Both MongoDB servers have the same version.")
else:
    print("\nResult: MongoDB server versions are different.")

atlas_client.close()
docker_client.close()