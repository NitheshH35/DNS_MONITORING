# backend/create_whois_cache.py
import sqlite3
from pathlib import Path

DB_PATH = Path("database.db").resolve().as_posix()

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS whois_cache (
    domain TEXT PRIMARY KEY,
    creation_date TEXT,
    fetched_at TEXT
)
""")
conn.commit()
conn.close()
print("✅ whois_cache table ensured in", DB_PATH)
