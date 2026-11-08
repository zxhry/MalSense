"""
Sprint 4 - Step 7: Check that Python can connect to the MalSense MySQL database.
Reads DB settings from the .env file (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME).
Usage: python tests/test_db.py
"""
import os
import pymysql
from dotenv import load_dotenv

load_dotenv()
cfg = dict(host=os.getenv("DB_HOST", "localhost"), user=os.getenv("DB_USER"),
           password=os.getenv("DB_PASSWORD"), database=os.getenv("DB_NAME", "malsense"))

print("=== DATABASE CONNECTION TEST ===")
print(f"Connecting to '{cfg['database']}' on {cfg['host']} as '{cfg['user']}' ...")
try:
    conn = pymysql.connect(**cfg)
except pymysql.err.OperationalError as e:
    print(f"FAILED: {e}")
    raise SystemExit(1)

with conn.cursor() as cur:
    cur.execute("SELECT VERSION()")
    print(f"Connected! MySQL version: {cur.fetchone()[0]}")
    cur.execute("SHOW TABLES")
    tables = [t[0] for t in cur.fetchall()]
    print(f"Tables found: {tables}")
    for t in tables:
        cur.execute(f"DESCRIBE {t}")
        cols = [row[0] for row in cur.fetchall()]
        cur.execute(f"SELECT COUNT(*) FROM {t}")
        print(f"  {t:<6} ({cur.fetchone()[0]} rows): {', '.join(cols)}")
conn.close()
print("OK - the app account can read the database.")