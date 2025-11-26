# backend/app.py
from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS
from flask_socketio import SocketIO
import sqlite3, csv, io, re, datetime as dt
import math
import tldextract
import idna
import whois
from datetime import datetime, timedelta
from collections import Counter
import os

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


# ---------- Layered detection pipeline (fast -> slow) ----------
# Tunable thresholds
ENTROPY_THRESHOLD = 3.5      # tune between 3.5..4.0
ENTROPY_MIN_LABEL_LEN = 8
NEW_DOMAIN_DAYS = 30         # consider domains <30 days as suspicious
WHOIS_CACHE_TTL_DAYS = 7     # refresh whois cache after 7 days

# static lists (tweak where needed)
SUSPICIOUS_TLDS = ('.ru', '.cc', '.xyz', '.top', '.kim', '.cn', '.tk', '.gq', '.ml', '.ga')
KEYWORDS = ('bot', 'freecdn', 'cdn', 'mal', 'tunnel', 'jwpcdn', 'amung', 'whos', 'mirror', 'crypto', 'miner', 'wallet', 'click', 'track', 'adserv')
BRAND_WORDS = ('google', 'facebook', 'instagram', 'microsoft', 'paypal', 'amazon', 'apple')
PHISH_WORDS = ('login', 'signin', 'verify', 'update', 'secure', 'support', 'reset')
LONG_LABEL_RE = re.compile(r'[a-z0-9]{16,}', re.I)

# optional local blocklist file (one domain per line)
BLOCKLIST = set()
BLOCKLIST_PATH = os.path.join(os.path.dirname(__file__), "blocklist.txt")
if os.path.exists(BLOCKLIST_PATH):
    with open(BLOCKLIST_PATH, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip().lower()
            if ln and not ln.startswith("#"):
                BLOCKLIST.add(ln)

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    ent = 0.0
    for v in freq.values():
        p = v / length
        ent -= p * math.log2(p)
    return ent

def whois_cached(domain: str):
    """
    Return creation_date as datetime or None.
    Uses whois_cache table to avoid repeated whois calls.
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # check cache
    cur.execute("SELECT creation_date, fetched_at FROM whois_cache WHERE domain = ?", (domain,))
    row = cur.fetchone()
    now = datetime.utcnow()
    if row:
        creation_date_str, fetched_at_str = row
        try:
            if fetched_at_str:
                fetched_at = datetime.fromisoformat(fetched_at_str)
                if (now - fetched_at).days <= WHOIS_CACHE_TTL_DAYS:
                    conn.close()
                    if not creation_date_str:
                        return None
                    return datetime.fromisoformat(creation_date_str)
        except Exception:
            pass

    # not cached or expired -> perform whois (slow)
    creation_date = None
    try:
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list) and cd:
            cd = cd[0]
        if isinstance(cd, datetime):
            creation_date = cd
        else:
            # attempt parse if string
            try:
                creation_date = datetime.fromisoformat(str(cd))
            except Exception:
                creation_date = None
    except Exception:
        creation_date = None

    # update cache
    try:
        cur.execute(
            "REPLACE INTO whois_cache (domain, creation_date, fetched_at) VALUES (?, ?, ?)",
            (domain, creation_date.isoformat() if creation_date else None, now.isoformat())
        )
        conn.commit()
    except Exception:
        pass
    conn.close()
    return creation_date

def detection_pipeline(domain: str) -> dict:
    """
    Returns dict:
      { 'flags': [...], 'confidence': 'low'|'medium'|'high', 'layers': {'1': [...], '2': [...], '3': [...]} }
    """
    flags = []
    layers = {'1': [], '2': [], '3': []}
    d = domain.lower().strip('.')

    # Blocklist exact or suffix match (fast)
    for bad in BLOCKLIST:
        if d == bad or d.endswith("." + bad):
            layers['1'].append('Blocklist')
            flags.append('Blocklist')
            return {'flags': flags, 'confidence': 'high', 'layers': layers}

    te = tldextract.extract(d)
    # choose main label: prefer leftmost subdomain or domain
    if te.subdomain:
        main_label = te.subdomain.split('.')[-1]
    else:
        main_label = te.domain or ''

    # ------ Layer 1: Static local checks (fast) ------
    if any(d.endswith(tld) for tld in SUSPICIOUS_TLDS):
        layers['1'].append('TLD'); flags.append('TLD')

    if any(k in d for k in KEYWORDS):
        layers['1'].append('Keyword'); flags.append('Keyword')

    if any(LONG_LABEL_RE.search(part) for part in d.split('.')):
        layers['1'].append('LongSubdomain'); flags.append('LongSubdomain')

    ent = calculate_entropy(main_label)
    if len(main_label) >= ENTROPY_MIN_LABEL_LEN and ent >= ENTROPY_THRESHOLD:
        layers['1'].append(f'HighEntropy:{ent:.2f}'); flags.append('HighEntropyLabel')

    # If layer1 already finds 2+ issues => high confidence and skip slow checks
    if len(layers['1']) >= 2:
        return {'flags': flags, 'confidence': 'high', 'layers': layers}

    # ------ Layer 2: Homograph / IDN / spoofing (medium) ------
    try:
        encoded = idna.encode(domain).decode('ascii')
        if encoded.startswith('xn--'):
            layers['2'].append(f'Punycode:{encoded}'); flags.append('IDN/Punycode')
    except idna.IDNAError:
        layers['2'].append('IDNError'); flags.append('IDNError')

    # Brand impersonation (brand + phishing word)
    for brand in BRAND_WORDS:
        if brand in d:
            for pw in PHISH_WORDS:
                if pw in d:
                    layers['2'].append(f'BrandImpersonation:{brand}')
                    flags.append(f'BrandImpersonation:{brand}')
                    break

    if layers['2']:
        return {'flags': flags, 'confidence': 'high' if layers['2'] else 'medium', 'layers': layers}

    # ------ Layer 3: Registration analysis / WHOIS (slow) ------
    # use registered_domain (example.com) or domain fallback
    registered = te.registered_domain or te.domain or d
    creation_date = whois_cached(registered)
    if creation_date:
        age_days = (datetime.utcnow() - creation_date).days
        layers['3'].append(f'AgeDays:{age_days}')
        if age_days >= 0 and age_days < NEW_DOMAIN_DAYS:
            flags.append('NewlyRegistered')
    else:
        layers['3'].append('WhoisUnknown')

    # Final confidence
    if flags:
        confidence = 'high' if ('TLD' in flags or any(f.startswith('BrandImpersonation') for f in flags) or 'NewlyRegistered' in flags) else 'medium'
    else:
        confidence = 'low'

    return {'flags': flags, 'confidence': confidence, 'layers': layers}


# ---------- Alerts endpoint (uses detection pipeline) ----------
@app.route('/alerts')
def alerts():
    # recent rows (domain, src_ip, timestamp)
    recent = q("""
        SELECT domain, src_ip, timestamp
        FROM dns_logs
        ORDER BY id DESC
        LIMIT 1000
    """)
    susp = []
    seen_domains = set()

    # dedupe — run expensive checks once per domain only
    for domain, src_ip, ts in recent:
        if not domain:
            continue
        if domain in seen_domains:
            continue
        seen_domains.add(domain)

        res = detection_pipeline(domain)
        if res['flags']:
            susp.append({
                'type': 'SuspiciousDomain',
                'domain': domain,
                'src_ip': src_ip,     # sample source IP (first seen in recent rows)
                'timestamp': ts,
                'flags': res['flags'],
                'confidence': res['confidence'],
                'layers': res['layers']
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
