# backend/app.py
from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS
from flask_socketio import SocketIO
import sqlite3, csv, io, re, datetime as dt

DB_PATH = r"C:\Users\Nithesh\OneDrive\Desktop\dns-monitoring\backend\database.db"

app = Flask(__name__, static_folder="../frontend")
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")  # WebSocket

# ---------- helpers ----------
def q(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.commit()
    conn.close()
    return rows

def rows_to_logs(rows):
    return [{'domain': r[0], 'src_ip': r[1], 'timestamp': r[2]} for r in rows]

# ---------- APIs ----------
@app.route('/logs')
def logs():
    rows = q("SELECT domain, src_ip, timestamp FROM dns_logs ORDER BY id DESC LIMIT 500")
    return jsonify(rows_to_logs(rows))

@app.route('/stats')
def stats():
    # top 10 domains
    top_domains = q("""
        SELECT domain, COUNT(*) as cnt
        FROM dns_logs
        GROUP BY domain
        ORDER BY cnt DESC
        LIMIT 10
    """)
    # top 10 source IPs
    top_ips = q("""
        SELECT src_ip, COUNT(*) as cnt
        FROM dns_logs
        GROUP BY src_ip
        ORDER BY cnt DESC
        LIMIT 10
    """)
    # queries per minute (last 60 minutes)
    per_min = q("""
        SELECT strftime('%Y-%m-%d %H:%M', timestamp) as minute, COUNT(*)
        FROM dns_logs
        WHERE timestamp >= datetime('now', '-60 minutes')
        GROUP BY minute
        ORDER BY minute ASC
    """)
    return jsonify({
        'topDomains': [{'domain': d, 'count': c} for d, c in top_domains],
        'topIPs': [{'ip': ip, 'count': c} for ip, c in top_ips],
        'perMinute': [{'minute': m, 'count': c} for m, c in per_min],
    })

# simple suspicious heuristics
SUSPICIOUS_TLDS = ('.ru', '.cc', '.xyz', '.top', '.kim')
KEYWORDS = ('bot', 'freecdn', 'cdn', 'mal', 'tunnel', 'jwpcdn', 'amung', 'whos', 'mirror')
LONG_LABEL = re.compile(r'[a-z0-9]{16,}', re.I)  # long random-looking label

def is_suspicious(domain: str) -> list[str]:
    flags = []
    d = domain.lower()
    if any(d.endswith(tld) for tld in SUSPICIOUS_TLDS): flags.append('TLD')
    if any(k in d for k in KEYWORDS): flags.append('Keyword')
    if any(LONG_LABEL.search(part) for part in d.strip('.').split('.')): flags.append('LongSubdomain')
    return flags

@app.route('/alerts')
def alerts():
    # suspicious by heuristics (last 1000 rows)
    recent = q("""
        SELECT domain, src_ip, timestamp
        FROM dns_logs
        ORDER BY id DESC
        LIMIT 1000
    """)
    susp = []
    for domain, src_ip, ts in recent:
        flags = is_suspicious(domain)
        if flags:
            susp.append({'type': 'SuspiciousDomain', 'domain': domain, 'src_ip': src_ip, 'timestamp': ts, 'flags': flags})

    # high frequency by IP (>= 60/min in last 1 min)
    burst = q("""
        SELECT src_ip, COUNT(*) as cnt
        FROM dns_logs
        WHERE timestamp >= datetime('now', '-1 minute')
        GROUP BY src_ip
        HAVING cnt >= 60
        ORDER BY cnt DESC
    """)
    freq = [{'type':'HighFrequency', 'src_ip': ip, 'count': c} for ip, c in burst]

    return jsonify({'alerts': susp + freq})

@app.route('/export/csv')
def export_csv():
    rows = q("SELECT domain, src_ip, timestamp FROM dns_logs ORDER BY id DESC")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['domain', 'src_ip', 'timestamp'])
    writer.writerows(rows)
    csv_data = output.getvalue()
    output.close()
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=dns_logs.csv'}
    )

# Real-time ingest endpoint (monitor.py will POST here)
@app.route('/ingest', methods=['POST'])
def ingest():
    data = request.get_json(force=True)
    domain = data.get('domain')
    src_ip = data.get('src_ip')
    ts = data.get('timestamp') or dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if not (domain and src_ip):
        return jsonify({'ok': False, 'error': 'missing fields'}), 400
    # insert
    q("INSERT INTO dns_logs (domain, src_ip, timestamp) VALUES (?, ?, ?)", (domain, src_ip, ts))
    # notify websocket clients
    socketio.emit('new_log', {'domain': domain, 'src_ip': src_ip, 'timestamp': ts})
    return jsonify({'ok': True})

# (Optional) serve built frontend if you ever run npm run build
@app.route('/')
def index():
    # If you decide to serve the built app from Flask, change to ../frontend/dist
    return send_from_directory("../frontend", "index.html")

if __name__ == "__main__":
    # Use eventlet for websocket support
    socketio.run(app, host="127.0.0.1", port=5000, debug=True)
