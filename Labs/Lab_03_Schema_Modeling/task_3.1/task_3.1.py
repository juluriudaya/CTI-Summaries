"""Task 3.1 - Design an Embedded Document Schema."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.connection import get_db, banner


COURSES = [
    {
        "course_name": "Introduction to Machine Learning",
        "course_code": "AIML101",
        "instructor": "Dr. Priya Sharma",
        "credits": 4,
        "schedule": {"days": ["Monday", "Wednesday"], "time": "10:00-11:30", "room": "LH-201"},
        "enrolled_students": [
            {"name": "Arjun Mehta", "email": "arjun@college.edu", "grade": "A"},
            {"name": "Sneha Reddy", "email": "sneha@college.edu", "grade": "B+"},
            {"name": "Rahul Kumar", "email": "rahul@college.edu", "grade": "A-"},
            {"name": "Divya Patel", "email": "divya@college.edu", "grade": "B"},
        ]
    },
    {
        "course_name": "Deep Learning with PyTorch",
        "course_code": "AIML301",
        "instructor": "Dr. Anil Gupta",
        "credits": 3,
        "schedule": {"days": ["Tuesday", "Thursday"], "time": "14:00-15:30", "room": "LH-305"},
        "enrolled_students": [
            {"name": "Arjun Mehta", "email": "arjun@college.edu", "grade": None},
            {"name": "Kavya Nair", "email": "kavya@college.edu", "grade": "A"},
            {"name": "Vikram Singh", "email": "vikram@college.edu", "grade": "A+"},
        ]
    },
    {
        "course_name": "Natural Language Processing",
        "course_code": "AIML201",
        "instructor": "Dr. Meera Joshi",
        "credits": 3,
        "schedule": {"days": ["Monday", "Wednesday", "Friday"], "time": "09:00-10:00", "room": "LH-102"},
        "enrolled_students": [
            {"name": "Sneha Reddy", "email": "sneha@college.edu", "grade": "B+"},
            {"name": "Rahul Kumar", "email": "rahul@college.edu", "grade": None},
            {"name": "Priya Das", "email": "priya.d@college.edu", "grade": "A-"},
            {"name": "Arjun Mehta", "email": "arjun@college.edu", "grade": None},
            {"name": "Neha Gupta", "email": "neha@college.edu", "grade": "B"},
        ]
    },
]


COURSE_VALIDATOR = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["course_name", "course_code", "instructor", "schedule", "enrolled_students"],
        "properties": {
            "course_name": {"bsonType": "string"},
            "course_code": {"bsonType": "string", "pattern": r"^[A-Z]{4}\d{3}$"},
            "instructor": {"bsonType": "string"},
            "credits": {"bsonType": "int", "minimum": 1, "maximum": 6},
            "schedule": {
                "bsonType": "object",
                "required": ["days", "time", "room"],
                "properties": {
                    "days": {"bsonType": "array", "items": {"bsonType": "string"}},
                    "time": {"bsonType": "string"},
                    "room": {"bsonType": "string"},
                }
            },
            "enrolled_students": {
                "bsonType": "array",
                "items": {
                    "bsonType": "object",
                    "required": ["name", "email"],
                    "properties": {
                        "name": {"bsonType": "string"},
                        "email": {"bsonType": "string"},
                        "grade": {"bsonType": ["string", "null"]},
                    }
                }
            },
        }
    }
}


def main():
    banner("Task 3.1: Embedded Document Schema Design")
    db = get_db("nosql_labs")

    if "courses" in db.list_collection_names():
        db.drop_collection("courses")
    db.create_collection("courses", validator=COURSE_VALIDATOR)
    col = db["courses"]
    print("[OK] Created 'courses' collection with JSON Schema validation.\n")

    col.insert_many(COURSES)
    print(f"[OK] Inserted {len(COURSES)} courses.\n")

    print("=== Courses on Monday ===")
    for course in col.find({"schedule.days": "Monday"}, {"course_name": 1, "schedule.days": 1, "_id": 0}):
        print(f"  {course['course_name']} ({', '.join(course['schedule']['days'])})")

    print("\n=== Courses by Dr. Priya Sharma ===")
    for course in col.find({"instructor": "Dr. Priya Sharma"}, {"course_name": 1, "enrolled_students": 1, "_id": 0}):
        names = [student["name"] for student in course["enrolled_students"]]
        print(f"  {course['course_name']}: {len(names)} students - {', '.join(names)}")

    print("\n=== Add new student to NLP course ===")
    col.update_one(
        {"course_code": "AIML201"},
        {"$push": {"enrolled_students": {"name": "Amit Verma", "email": "amit@college.edu", "grade": None}}}
    )
    updated = col.find_one({"course_code": "AIML201"})
    print(f"  Students in NLP now: {len(updated['enrolled_students'])}")

    print("\n=== Testing Validation ===")
    try:
        col.insert_one({"course_name": "Invalid Course", "instructor": "Nobody"})
        print("  [ERROR] Validation should have failed!")
    except Exception as error:
        print(f"  [OK] Validation caught error: {error.details['errmsg'][:80]}...")

    print("\n=== Arjun Mehta's Courses ===")
    for course in col.find(
        {"enrolled_students.email": "arjun@college.edu"},
        {"course_name": 1, "course_code": 1, "schedule.time": 1, "_id": 0},
    ):
        print(f"  {course['course_code']}: {course['course_name']} ({course['schedule']['time']})")

    banner("Task 3.1 Complete")


if __name__ == "__main__":
    main()