"""Lab 5.1: Build a Sales Analytics Pipeline.
Run: python lab_5_1.py
Requires: pip install pymongo
MongoDB must be running at mongodb://localhost:27017.
"""
import json
from pathlib import Path
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
client.admin.command("ping")
db = client["lab5_sales"]
orders = db["orders"]
orders.delete_many({})
data = json.loads(Path(__file__).with_suffix(".json").read_text(encoding="utf-8"))
orders.insert_many(data)
print(f"Inserted {len(data)} orders into lab5_sales.orders")

print("\n1) MONTHLY REVENUE")
monthly_pipeline = [
    {"$addFields": {"_order_date": {"$dateFromString": {"dateString": "$order_date"}}}},
    {"$match": {"status": {"$in": ["completed", "shipped"]}}},
    {"$group": {
        "_id": {"$dateToString": {"format": "%Y-%m", "date": "$_order_date"}},
        "monthly_revenue": {"$sum": {"$multiply": ["$quantity", "$unit_price"]}},
        "order_count": {"$sum": 1}
    }},
    {"$sort": {"_id": 1}},
    {"$project": {"_id": 0, "month": "$_id", "monthly_revenue": 1, "order_count": 1}}
]
for row in orders.aggregate(monthly_pipeline):
    print(f"{row['month']}: revenue={row['monthly_revenue']:.2f}, orders={row['order_count']}")

print("\n2) TOP 3 CUSTOMERS BY TOTAL SPENDING")
top_customers_pipeline = [
    {"$match": {"status": {"$in": ["completed", "shipped"]}}},
    {"$addFields": {"order_value": {"$multiply": ["$quantity", "$unit_price"]}}},
    {"$group": {
        "_id": "$customer",
        "total_spending": {"$sum": "$order_value"},
        "products_bought": {"$addToSet": "$product"},
        "order_count": {"$sum": 1}
    }},
    {"$sort": {"total_spending": -1}},
    {"$limit": 3},
    {"$project": {"_id": 0, "customer": "$_id", "total_spending": 1,
                  "products_bought": 1, "order_count": 1}}
]
for row in orders.aggregate(top_customers_pipeline):
    print(f"{row['customer']}: {row['total_spending']:.2f}; "
          f"orders={row['order_count']}; products={', '.join(sorted(row['products_bought']))}")

print("\n3) AVERAGE ORDER VALUE BY STATUS")
status_pipeline = [
    {"$addFields": {"order_value": {"$multiply": ["$quantity", "$unit_price"]}}},
    {"$group": {
        "_id": "$status",
        "average_order_value": {"$avg": "$order_value"},
        "order_count": {"$sum": 1}
    }},
    {"$sort": {"_id": 1}},
    {"$project": {"_id": 0, "status": "$_id", "average_order_value": 1, "order_count": 1}}
]
for row in orders.aggregate(status_pipeline):
    print(f"{row['status']}: average={row['average_order_value']:.2f}, "
          f"orders={row['order_count']}")

client.close()
