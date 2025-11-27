# backend/create_db.py
import sqlite3
from pathlib import Path

DB_PATH = Path("database.db").resolve().as_posix()

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS dns_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    timestamp TEXT
)
""")

conn.commit()
conn.close()
print("✅ database and dns_logs table created at:", DB_PATH)
