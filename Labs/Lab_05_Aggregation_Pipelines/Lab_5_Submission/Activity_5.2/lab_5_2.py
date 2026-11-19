"""Lab 5.2: Join order and product data with $lookup.
Run: python lab_5_2.py
Requires: pip install pymongo and local MongoDB.
"""
import json
from pathlib import Path
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
client.admin.command("ping")
db = client["lab5_lookup"]
orders = db["orders"]
products = db["products"]
orders.delete_many({})
products.delete_many({})
orders_data = json.loads(Path(__file__).with_name("lab_5_2_orders.json").read_text(encoding="utf-8"))
products_data = json.loads(Path(__file__).with_name("lab_5_2_products.json").read_text(encoding="utf-8"))
orders.insert_many(orders_data)
products.insert_many(products_data)
print(f"Inserted {len(orders_data)} orders and {len(products_data)} products")

print("\n1) ORDERS JOINED WITH PRODUCT DETAILS")
join_pipeline = [
    {"$lookup": {
        "from": "products",
        "localField": "product_id",
        "foreignField": "product_id",
        "as": "product"
    }},
    {"$unwind": "$product"},
    {"$addFields": {"computed_total": {"$multiply": ["$quantity", "$product.base_price"]}}},
    {"$project": {
        "_id": 0, "order_date": 1, "order_id": 1,
        "product_name": "$product.name", "quantity": 1,
        "computed_total": 1
    }},
    {"$sort": {"order_date": 1, "order_id": 1}}
]
for row in orders.aggregate(join_pipeline):
    print(f"{row['order_date']} | {row['order_id']} | {row['product_name']} | "
          f"qty={row['quantity']} | total=${row['computed_total']:.2f}")

print("\n2) PRODUCTS THAT HAVE NEVER BEEN ORDERED")
never_ordered_pipeline = [
    {"$lookup": {
        "from": "orders",
        "localField": "product_id",
        "foreignField": "product_id",
        "as": "matching_orders"
    }},
    {"$match": {"matching_orders": {"$size": 0}}},
    {"$project": {"_id": 0, "product_id": 1, "name": 1, "category": 1, "base_price": 1}}
]
for row in products.aggregate(never_ordered_pipeline):
    print(f"{row['product_id']} | {row['name']} | {row['category']} | ${row['base_price']:.2f}")

client.close()
