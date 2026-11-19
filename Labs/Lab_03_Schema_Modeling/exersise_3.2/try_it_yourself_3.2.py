"""
Activity 3.2 - Try It Yourself

Scenario:
A post has 10,000 comments.

Decision:
Use a referenced design instead of embedding all comments.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.connection import get_db, reset_collection, banner


def main():
    banner("Activity 3.2: Try It Yourself")

    db = get_db("nosql_labs")

    # Use separate collections
    posts_col = reset_collection("nosql_labs", "large_posts")
    comments_col = reset_collection("nosql_labs", "large_comments")

    # Create one post
    post = {
    "title": "Post with 10,000 Comments",
    "author": "student",
    "image_path": r"C:\Users\Julur\OneDrive\Pictures\Screenshots\Screenshot 2026-09-05 154141.png"
}

    post_id = posts_col.insert_one(post).inserted_id

    # Create 10,000 separate comments
    comments = []

    for i in range(10000):
        comments.append({
            "post_id": post_id,
            "text": f"This is comment number {i + 1}",
            "author": f"reader{i + 1}"
        })

    comments_col.insert_many(comments)

    print("[OK] Inserted 1 post")
    print("[OK] Inserted 10,000 comments")

    # Query the post
    stored_post = posts_col.find_one({"_id": post_id})

    # Query all comments belonging to the post
    post_comments = comments_col.find({"post_id": post_id})

    comment_count = comments_col.count_documents({"post_id": post_id})

    print("\n=== Design Decision ===")
    print("Design: Referenced")
    print("Reason: 10,000 comments would make embedding problematic.")
    print("Comments are stored separately and linked using post_id.")

    print("\n=== Query Result ===")
    print(f"Post: {stored_post['title']}")
    print(f"Comments: {comment_count}")

    print("\n=== Why Referencing? ===")
    print("1. Avoids creating one extremely large post document.")
    print("2. Comments can be added independently.")
    print("3. Individual comments can be updated or deleted easily.")
    print("4. Large comment collections can be queried separately.")

    banner("Try It Yourself 3.2 Complete")


if __name__ == "__main__":
    main()