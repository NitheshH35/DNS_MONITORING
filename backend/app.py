from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
from flask_cors import CORS
# We still need this import, but we are not calling init_db()
from models import init_db 

app = Flask(__name__, static_folder="../frontend")
CORS(app) # Lets frontend talk to backend

# init_db() call is GONE. Database is safe.

@app.route('/logs')
def get_logs():
    # This route is correct and your frontend uses it.
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT domain, src_ip, timestamp FROM dns_logs ORDER BY id DESC LIMIT 50")
        rows = cursor.fetchall()
        conn.close()

        logs = [{'domain': r[0], 'src_ip': r[1], 'timestamp': r[2]} for r in rows]
        return jsonify(logs)
    except Exception as e:
        print(f"Error in /logs: {e}")
        return jsonify({'error': str(e)})

@app.route('/')
def index():
    # This route serves your frontend's index.html file
    return send_from_directory("../frontend", "index.html")

# --- THIS IS THE FIXED ROUTE ---
@app.route('/api/dns')
def get_dns_logs():
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # --- FIX 1: We only SELECT the columns that monitor.py saves ---
        c.execute("SELECT id, domain, src_ip, timestamp FROM dns_logs ORDER BY id DESC LIMIT 50")
        rows = c.fetchall()
        conn.close()

        # --- FIX 2: We map those 4 columns to the keys you wanted ---
        data = [
            {
                "id": r[0],
                "query_name": r[1],   # Was r[2], now maps from 'domain'
                "source_ip": r[2],    # Was r[4], now maps from 'src_ip'
                "timestamp": r[3],    # Was r[1], now maps from 'timestamp'
                
                # I removed the other keys that don't exist in the database:
                # "query_type", "destination_ip", "response_ip", "status"
            }
            for r in rows
        ]
        return jsonify(data)
    except Exception as e:
        print(f"Error in /api/dns: {e}")
        return jsonify({'error': str(e)})

if __name__ == "__main__":
    app.run(debug=True, port=5000)