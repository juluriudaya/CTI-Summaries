$ErrorActionPreference = "Stop"
$env:MONGO_URI = "mongodb://127.0.0.1:27223"

Write-Host "Starting Lab 18 MongoDB..."
docker compose up -d mongodb

Write-Host "Checking MongoDB..."
python -c "from pymongo import MongoClient; c=MongoClient('$env:MONGO_URI',serverSelectionTimeoutMS=5000); print(c.admin.command('ping'))"

Write-Host "Running Lab 18.1..."
python lab_01_comparative_capstone.py

Write-Host "Running Lab 18.2..."
python lab_02_comparative_report.py
