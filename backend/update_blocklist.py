import requests

SOURCES = [
    "https://v.firebog.net/hosts/Prigent-Malware.txt",
    "https://v.firebog.net/hosts/Prigent-Phishing.txt",
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://phishing.army/download/phishing_army_blocklist.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt",
]

OUTPUT = "blocklist.txt"

all_domains = set()

for url in SOURCES:
    print(f"Downloading {url}...")
    try:
        data = requests.get(url, timeout=10).text
        for line in data.splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#") and "." in line:
                all_domains.add(line)
    except:
        print(f"Failed: {url}")

with open(OUTPUT, "w", encoding="utf-8") as f:
    for d in sorted(all_domains):
        f.write(d + "\n")

print(f"Saved {len(all_domains)} domains to blocklist.txt")
