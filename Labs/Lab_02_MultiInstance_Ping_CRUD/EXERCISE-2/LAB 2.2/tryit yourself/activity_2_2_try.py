from pymongo import MongoClient

# Connect to Docker MongoDB
client = MongoClient("mongodb://localhost:27017")

# Select database and collection
db = client["booksstore"]
books = db["books"]

# Start with a fresh collection
books.delete_many({})

# Original book data
book_data = [
    {
        "title": "The Pragmatic Programmer",
        "author": "David Thomas & Andrew Hunt",
        "year": 2019,
        "genre": "Software Engineering",
        "price": 49.99
    },
    {
        "title": "Designing Data-Intensive Applications",
        "author": "Martin Kleppmann",
        "year": 2017,
        "genre": "Databases",
        "price": 45.99
    },
    {
        "title": "Deep Learning",
        "author": "Ian Goodfellow, Yoshua Bengio, Aaron Courville",
        "year": 2016,
        "genre": "Machine Learning",
        "price": 72.00
    },
    {
        "title": "Clean Code",
        "author": "Robert C. Martin",
        "year": 2008,
        "genre": "Software Engineering",
        "price": 39.99
    },
    {
        "title": "Hands-On Machine Learning",
        "author": "Aurelien Geron",
        "year": 2022,
        "genre": "Machine Learning",
        "price": 59.99
    }
]

# Insert fresh data
insert_result = books.insert_many(book_data)

print("Inserted", len(insert_result.inserted_ids), "books.")

# Before 2010: +10%
result1 = books.update_many(
    {"year": {"$lt": 2010}},
    {"$mul": {"price": 1.10}}
)

# 2010-2020: +5%
result2 = books.update_many(
    {"year": {"$gte": 2010, "$lte": 2020}},
    {"$mul": {"price": 1.05}}
)

# After 2020: unchanged
after_2020 = books.count_documents(
    {"year": {"$gt": 2020}}
)

print("\nBooks updated before 2010:", result1.modified_count)
print("Books updated from 2010 to 2020:", result2.modified_count)
print("Books after 2020 left unchanged:", after_2020)

# Verification using find_one()
print("\nVerification:")

print(
    "Before 2010:",
    books.find_one(
        {"year": {"$lt": 2010}},
        {"_id": 0, "title": 1, "year": 1, "price": 1}
    )
)

print(
    "2010-2020:",
    books.find_one(
        {"year": {"$gte": 2010, "$lte": 2020}},
        {"_id": 0, "title": 1, "year": 1, "price": 1}
    )
)

print(
    "After 2020:",
    books.find_one(
        {"year": {"$gt": 2020}},
        {"_id": 0, "title": 1, "year": 1, "price": 1}
    )
)

client.close()