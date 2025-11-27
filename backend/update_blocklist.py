# backend/update_blocklist.py
import requests
from pathlib import Path

SOURCES = [
    "https://v.firebog.net/hosts/Prigent-Malware.txt",
    "https://v.firebog.net/hosts/Prigent-Phishing.txt",
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://phishing.army/download/phishing_army_blocklist.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt",
]

OUT = Path("blocklist.txt")

domains = set()
for url in SOURCES:
    print("Downloading", url)
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            for ln in r.text.splitlines():
                ln = ln.strip().lower()
                if not ln or ln.startswith("#"):
                    continue
                # Some lists include hosts file format that starts with 0.0.0.0 example.com
                parts = ln.split()
                if len(parts) >= 1:
                    item = parts[-1]
                else:
                    item = ln
                if "." in item and len(item) > 3:
                    domains.add(item)
        else:
            print("Failed to download:", url, "status:", r.status_code)
    except Exception as e:
        print("Error downloading", url, e)

print("Total domains collected:", len(domains))
OUT.write_text("\n".join(sorted(domains)), encoding="utf-8")
print("Saved to", OUT)
