# ============================================================
# ACTIVITY FOR 6.1
# Measure Actual Index Usage using $indexStats
# ============================================================

import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.connection import get_db, reset_collection, banner


banner("ACTIVITY 6.1 - INDEX USAGE")


def generate_products(count=250):
    """Create product documents with fields that match common query patterns."""
    categories = ["Electronics", "Books", "Home", "Clothing", "Toys"]
    tag_pool = ["sale", "new", "featured", "bestseller", "clearance", "premium"]
    products = []

    for i in range(1, count + 1):
        category = categories[i % len(categories)]
        price = random.randint(300, 120000)
        rating = round(random.uniform(2.5, 5.0), 1)

        name = f"Product {i}"
        if i % 8 == 0:
            name = "Gaming Laptop Pro"
        elif i % 7 == 0:
            name = "Wireless Bluetooth Speaker"
        elif i % 6 == 0:
            name = "Python Programming Guide"

        description = f"{name} for everyday use in {category.lower()}"
        tags = random.sample(tag_pool, random.randint(1, 3))

        products.append({
            "_id": i,
            "name": name,
            "category": category,
            "price": price,
            "rating": rating,
            "tags": tags,
            "description": description,
        })

    return products


# ------------------------------------------------------------
# 1. Prepare data and create indexes
# ------------------------------------------------------------

products = reset_collection("nosql_labs", "products")

if products.count_documents({}) == 0:
    products.insert_many(generate_products())

products.create_index([("category", 1), ("price", 1)], name="idx_category_price")
products.create_index([("price", 1)], name="idx_price")
products.create_index([("tags", 1)], name="idx_tags")
products.create_index([("category", 1), ("rating", -1)], name="idx_category_rating")
products.create_index([("name", "text"), ("description", "text")], name="idx_text_search")

print("\nRunning queries multiple times...")

# ------------------------------------------------------------
# 2. Run the five queries multiple times
# ------------------------------------------------------------

for _ in range(20):
    # Query 1: Category + Sort by Price
    list(
        products.find({"category": "Electronics"})
        .sort("price", 1)
        .limit(10)
    )

    # Query 2: Price Range
    list(
        products.find({
            "price": {"$gte": 10000, "$lte": 50000}
        }).limit(10)
    )

    # Query 3: Find by Tag
    list(
        products.find({"tags": "sale"}).limit(10)
    )

    # Query 4: Text Search
    list(
        products.find({"$text": {"$search": "Laptop"}}).limit(10)
    )

    # Query 5: Category + Rating
    list(
        products.find({
            "category": "Books",
            "rating": {"$gte": 4}
        }).sort("rating", -1).limit(10)
    )

print("Queries executed 20 times.")

# ------------------------------------------------------------
# 3. Check index usage using $indexStats
# ------------------------------------------------------------

print("\n==============================================")
print("INDEX USAGE STATISTICS")
print("==============================================")

index_stats = list(products.aggregate([{"$indexStats": {}}]))

# ------------------------------------------------------------
# 4. Display index usage
# ------------------------------------------------------------

for index in index_stats:
    index_name = index["name"]
    operations = index["accesses"]["ops"]
    since = index["accesses"]["since"]
    print(f"\nIndex: {index_name}")
    print(f"Operations used: {operations}")
    print(f"Tracking since: {since}")

print("\n==============================================")
print("INDEX USAGE ANALYSIS")
print("==============================================")