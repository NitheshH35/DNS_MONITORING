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
    # rows = SELECT domain, src_ip, dst_ip, timestamp ...
    return [
        {
            "domain": r[0],
            "src_ip": r[1],
            "dst_ip": r[2],
            "timestamp": r[3],
        }
        for r in rows
    ]

# ---------- APIs ----------
@app.route('/logs')
def logs():
    # now also selecting dst_ip
    rows = q(
        "SELECT domain, src_ip, dst_ip, timestamp FROM dns_logs ORDER BY id DESC LIMIT 500"
    )
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

# ---------- Suspicious domain heuristics (advanced) ----------

SUSPICIOUS_TLDS = (
    '.ru', '.cc', '.xyz', '.top', '.kim', '.cn', '.tk', '.gq', '.ml', '.ga'
)

KEYWORDS = (
    'bot', 'freecdn', 'cdn', 'mal', 'tunnel', 'jwpcdn', 'amung', 'whos',
    'mirror', 'crypto', 'miner', 'wallet', 'click', 'track', 'adserv'
)

# Possible brand phishing patterns (fake login pages)
BRAND_WORDS = (
    'google', 'facebook', 'instagram', 'microsoft', 'paypal', 'amazon', 'apple'
)
PHISH_WORDS = (
    'login', 'signin', 'verify', 'update', 'secure', 'support', 'reset'
)

LONG_LABEL = re.compile(r'[a-z0-9]{16,}', re.I)  # long random-looking label


def shannon_entropy(s: str) -> float:
    """Rough measure of randomness: higher = more random."""
    if not s:
        return 0.0
    from math import log2
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    length = len(s)
    for c in freq.values():
        p = c / length
        ent -= p * log2(p)
    return ent


def is_suspicious(domain: str) -> list[str]:
    flags: list[str] = []
    d = domain.lower().strip('.')
    parts = d.split('.')

    # 1) TLD heuristic
    if any(d.endswith(tld) for tld in SUSPICIOUS_TLDS):
        flags.append('TLD')

    # 2) Simple keyword heuristic
    if any(k in d for k in KEYWORDS):
        flags.append('Keyword')

    # 3) Very long random-looking subdomain label
    for part in parts:
        if LONG_LABEL.search(part):
            flags.append('LongSubdomain')
            break

    # 4) High entropy = random DGA-like labels
    # Check only the left-most label (before first dot)
    main_label = parts[0] if parts else ""
    ent = shannon_entropy(main_label)
    if len(main_label) >= 12 and ent >= 3.5:
        flags.append('HighEntropyLabel')

    # 5) Many subdomains (deep nesting) – often used to hide stuff
    if len(parts) >= 5:
        flags.append('DeepSubdomainChain')

    # 6) Brand impersonation (brand + phishing word)
    for brand in BRAND_WORDS:
        if brand in d:
            for pw in PHISH_WORDS:
                if pw in d:
                    flags.append(f'BrandImpersonation:{brand}')
                    break

    # 7) Mix of letters and digits in long label (common in malware beacons)
    if len(main_label) >= 10:
        has_digit = any(ch.isdigit() for ch in main_label)
        has_alpha = any(ch.isalpha() for ch in main_label)
        if has_digit and has_alpha:
            flags.append('AlphaNumericLabel')

    return flags


@app.route('/alerts')
def alerts():
    # suspicious by heuristics (last 1000 rows)
    # we only need domain, src_ip, timestamp here
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
            susp.append({
                'type': 'SuspiciousDomain',
                'domain': domain,
                'src_ip': src_ip,
                'timestamp': ts,
                'flags': flags
            })

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
    # include dst_ip in export as well
    rows = q("SELECT domain, src_ip, dst_ip, timestamp FROM dns_logs ORDER BY id DESC")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['domain', 'src_ip', 'dst_ip', 'timestamp'])
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
    dst_ip = data.get('dst_ip')   # 👈 NEW
    ts = data.get('timestamp') or dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if not (domain and src_ip):
        return jsonify({'ok': False, 'error': 'missing fields'}), 400

    # insert with dst_ip
    q(
        "INSERT INTO dns_logs (domain, src_ip, dst_ip, timestamp) VALUES (?, ?, ?, ?)",
        (domain, src_ip, dst_ip, ts)
    )

    # notify websocket clients (frontend expects dst_ip field)
    socketio.emit('new_log', {
        'domain': domain,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'timestamp': ts
    })

    return jsonify({'ok': True})

# (Optional) serve built frontend if you ever run npm run build
@app.route('/')
def index():
    # If you decide to serve the built app from Flask, change to ../frontend/dist
    return send_from_directory("../frontend", "index.html")

if __name__ == "__main__":
    # Use eventlet for websocket support
    socketio.run(app, host="127.0.0.1", port=5000, debug=True)
