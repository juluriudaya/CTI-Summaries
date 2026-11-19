from pymongo import MongoClient

# MongoDB Atlas connection
atlas_uri = "YOUR_ATLAS_CONNECTION_STRING"
atlas_client = MongoClient(atlas_uri)

# Docker MongoDB connection
docker_client = MongoClient("mongodb://localhost:27017")

# Get server information
atlas_info = atlas_client.server_info()
docker_info = docker_client.server_info()

# Display versions
print("MongoDB Atlas Version :", atlas_info["version"])
print("Docker MongoDB Version:", docker_info["version"])

# Compare versions
if atlas_info["version"] == docker_info["version"]:
    print("Result: Both MongoDB servers have the same version.")
else:
    print("Result: MongoDB server versions are different.")

# Close connections
atlas_client.close()
docker_client.close()
