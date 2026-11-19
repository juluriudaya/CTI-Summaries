"""Lab 5.1 Try It Yourself: Categorize orders with $bucket.
Small: below $50; Medium: $50 through $200; Large: above $200.
Run: python lab_5_1_bucket.py
"""
import json
from pathlib import Path
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
client.admin.command("ping")
orders = client["lab5_sales_bucket"]["orders"]
orders.delete_many({})
data = json.loads(Path(__file__).with_suffix(".json").read_text(encoding="utf-8"))
orders.insert_many(data)

pipeline = [
    {"$addFields": {"order_value": {"$multiply": ["$quantity", "$unit_price"]}}},
    {"$bucket": {
        "groupBy": "$order_value",
        "boundaries": [0, 50, 200.01],
        "default": "large",
        "output": {
            "order_count": {"$sum": 1},
            "total_revenue": {"$sum": "$order_value"},
            "orders": {"$push": "$order_id"}
        }
    }},
    {"$project": {
        "_id": 0,
        "size": {"$switch": {
            "branches": [
                {"case": {"$eq": ["$_id", 0]}, "then": "small (< $50)"},
                {"case": {"$eq": ["$_id", 50]}, "then": "medium ($50-$200)"}
            ],
            "default": "large (> $200)"
        }},
        "order_count": 1, "total_revenue": 1, "orders": 1
    }}
]
print("ORDER VALUE BUCKETS")
for row in orders.aggregate(pipeline):
    print(f"{row['size']}: {row['order_count']} orders, "
          f"total=${row['total_revenue']:.2f}, IDs={', '.join(row['orders'])}")
client.close()
