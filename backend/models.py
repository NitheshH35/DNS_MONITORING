import sqlite3

DB_PATH = "database.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create dns_logs table if it does not exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()
    print("✅ Database initialized with table 'dns_logs'.")
