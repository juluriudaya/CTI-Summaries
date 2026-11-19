from pymongo import MongoClient

# Connect to Docker MongoDB
client = MongoClient("mongodb://localhost:27017")

# Select database and collection
db = client["booksstore"]
books = db["books"]

# Show books before update
print("Prices BEFORE update:")
for book in books.find({}, {"_id": 0, "title": 1, "year": 1, "price": 1}):
    print(book)

# Increase price by 10% for books published before 2010
result = books.update_many(
    {"year": {"$lt": 2010}},
    {"$mul": {"price": 1.10}}
)

print("\nNumber of books updated:", result.modified_count)

# Show books after update
print("\nPrices AFTER update:")
for book in books.find({}, {"_id": 0, "title": 1, "year": 1, "price": 1}):
    print(book)

client.close()