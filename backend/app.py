# backend/app.py
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
from models import init_db

# ✅ Use ABSOLUTE PATH to database
DB_PATH = r"C:\Users\Nithesh\OneDrive\Desktop\dns-monitoring\backend\database.db"

app = Flask(__name__, static_folder="../frontend")
CORS(app)   # ✅ allow frontend (port 5173) to access backend (port 5000)

init_db()

@app.route('/logs')
def get_logs():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT domain, src_ip, timestamp FROM dns_logs ORDER BY id DESC LIMIT 50")
        rows = cursor.fetchall()
        conn.close()

        logs = [{'domain': r[0], 'src_ip': r[1], 'timestamp': r[2]} for r in rows]
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/')
def index():
    return send_from_directory("../frontend", "index.html")

# This API is NOT needed, but keeping it usable:
@app.route('/api/dns')
def get_dns_logs():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT domain, src_ip, timestamp FROM dns_logs ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()

    data = [
        {
            "domain": r[0],
            "src_ip": r[1],
            "timestamp": r[2]
        }
        for r in rows
    ]
    return jsonify(data)

if __name__ == "__main__":
    app.run(debug=True)
