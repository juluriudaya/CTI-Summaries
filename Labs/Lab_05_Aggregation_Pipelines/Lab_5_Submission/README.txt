LAB 5.1 AND LAB 5.2 - MONGODB AGGREGATION AND LOOKUP

Contents:
- Activity_5.1: Monthly revenue, top 3 customers with products bought, average order value by status.
- Activity_5.1_Try_Yourself: $bucket categorization (small, medium, large).
- Activity_5.2: $lookup join, computed totals, products never ordered.
- Activity_5.2_Try_Yourself: $lookup with a foreign-side pipeline filter (quantity >= 2).
- Lab_5_Report.docx: All scripts and output preview screenshots.

Requirements:
1. Install Python 3.9+.
2. Install dependency: pip install pymongo
3. Start MongoDB locally at mongodb://localhost:27017/
4. Run each Python script from its own folder:
   python lab_5_1.py
   python lab_5_1_bucket.py
   python lab_5_2.py
   python lab_5_2_lookup_pipeline.py

Important:
- Each script reads its matching JSON dataset from the same directory.
- Scripts clear only their own target collections before inserting the sample dataset.
- Lab 5.1 monthly revenue and top customers count completed and shipped orders as sales.
- Lab 5.1 average order value is calculated for all status categories.
- Bucket definitions: small < $50; medium $50 through $200; large > $200.
- Screenshots in the DOCX are generated output previews from the included datasets.
  Run the scripts against MongoDB to obtain live terminal output in your environment.
