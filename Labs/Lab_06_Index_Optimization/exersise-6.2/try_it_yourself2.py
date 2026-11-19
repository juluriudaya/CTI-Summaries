# ============================================================
# ACTIVITY 6.2 - COVERED QUERY
# ============================================================

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.connection import get_db, reset_collection, banner


banner("ACTIVITY 6.2 - COVERED QUERY")

# ------------------------------------------------------------
# 1. Prepare collection and index
# ------------------------------------------------------------

db = get_db("nosql_labs")
col_5 = reset_collection("nosql_labs", "sensor_covered_demo")

sample_docs = [{
    "sensor_id": f"SENSOR-{i:04d}",
    "reading": float(i),
    "status": "active",
    "location": "lab-a" if i % 2 == 0 else "lab-b"
} for i in range(2000)]

if col_5.count_documents({}) == 0:
    col_5.insert_many(sample_docs)

col_5.create_index(
    [("sensor_id", 1), ("reading", 1)],
    name="idx_sensor_reading_covered"
)

print("Covered-query index created.")


# ------------------------------------------------------------
# 2. Create a covered query
# ------------------------------------------------------------

covered_query = {
    "sensor_id": "SENSOR-0050"
}

projection = {
    "_id": 0,
    "sensor_id": 1,
    "reading": 1
}


# ------------------------------------------------------------
# 3. Run explain()
# ------------------------------------------------------------

explain_result = db.command(
    "explain",
    {"find": col_5.name, "filter": covered_query, "projection": projection},
    verbosity="executionStats",
)

# ------------------------------------------------------------
# 4. Display execution plan
# ------------------------------------------------------------

print("\nQuery:")
print(covered_query)

print("\nProjection:")
print(projection)

winning_plan = explain_result["queryPlanner"]["winningPlan"]
print("\nWinning Plan:")
print(winning_plan)

execution_stats = explain_result.get("executionStats", {})
print("\nTotal Documents Examined:", execution_stats.get("totalDocsExamined"))
print("Total Keys Examined:", execution_stats.get("totalKeysExamined"))
print("Execution Time:", execution_stats.get("executionTimeMillis"), "ms")


# ------------------------------------------------------------
# 5. Check whether FETCH exists
# ------------------------------------------------------------

plan_string = str(winning_plan)

if "FETCH" not in plan_string:
    print("\nSUCCESS: FETCH stage is eliminated.")
    print("This is a COVERED QUERY.")
else:
    print("\nFETCH stage is present.")
    print("Query is NOT fully covered.")