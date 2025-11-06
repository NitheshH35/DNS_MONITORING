# backend/app.py
from flask import Flask, jsonify, send_from_directory
import sqlite3
from models import init_db

app = Flask(__name__, static_folder="../frontend")

init_db()
@app.route('/logs')
def get_logs():
    try:
        conn = sqlite3.connect('database.db')
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

@app.route('/api/dns')
def get_dns_logs():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM dns_logs ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()

    data = [
        {
            "id": r[0],
            "timestamp": r[1],
            "query_name": r[2],
            "query_type": r[3],
            "source_ip": r[4],
            "destination_ip": r[5],
            "response_ip": r[6],
            "status": r[7]
        }
        for r in rows
    ]
    return jsonify(data)

if __name__ == "__main__":
    app.run(debug=True)
