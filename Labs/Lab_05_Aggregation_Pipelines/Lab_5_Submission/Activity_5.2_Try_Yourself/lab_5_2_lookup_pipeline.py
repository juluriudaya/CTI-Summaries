"""Lab 5.2 Try It Yourself: $lookup with a foreign-side pipeline.
This example returns each product with only orders where quantity >= 2.
Run: python lab_5_2_lookup_pipeline.py
"""
import json
from pathlib import Path
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
client.admin.command("ping")
db = client["lab5_lookup_pipeline"]
orders = db["orders"]
products = db["products"]
orders.delete_many({})
products.delete_many({})
orders_data = json.loads(Path(__file__).with_name("lab_5_2_pipeline_orders.json").read_text(encoding="utf-8"))
products_data = json.loads(Path(__file__).with_name("lab_5_2_pipeline_products.json").read_text(encoding="utf-8"))
orders.insert_many(orders_data)
products.insert_many(products_data)

pipeline = [
    {"$lookup": {
        "from": "orders",
        "let": {"current_product_id": "$product_id"},
        "pipeline": [
            {"$match": {"$expr": {"$and": [
                {"$eq": ["$product_id", "$$current_product_id"]},
                {"$gte": ["$quantity", 2]}
            ]}}},
            {"$project": {"_id": 0, "order_id": 1, "order_date": 1, "quantity": 1}},
            {"$sort": {"order_date": 1}}
        ],
        "as": "qualifying_orders"
    }},
    {"$project": {
        "_id": 0, "product_id": 1, "name": 1,
        "qualifying_order_count": {"$size": "$qualifying_orders"},
        "qualifying_orders": 1
    }},
    {"$sort": {"name": 1}}
]
print("PRODUCTS WITH MATCHING ORDERS (quantity >= 2)")
for row in products.aggregate(pipeline):
    print(f"{row['product_id']} | {row['name']} | "
          f"qualifying orders={row['qualifying_order_count']}")
    for order in row["qualifying_orders"]:
        print(f"    {order['order_id']} | {order['order_date']} | qty={order['quantity']}")
client.close()
