import sqlite3

# Connect (creates database.db if it doesn't exist)
conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# Create the table for storing DNS logs
cursor.execute("""
CREATE TABLE IF NOT EXISTS dns_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    src_ip TEXT,
    timestamp TEXT
)
""")

conn.commit()
conn.close()

print("✅ Database and table created successfully!")
