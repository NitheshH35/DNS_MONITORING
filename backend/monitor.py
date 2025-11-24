# backend/monitor.py
from scapy.all import sniff, DNS, DNSQR, IP, IPv6
from datetime import datetime
import requests

INGEST_URL = "http://127.0.0.1:5000/ingest"


def process_packet(packet):
    # Only process DNS queries (qr == 0 = query, qr == 1 = response)
    if not (packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 and packet.haslayer(DNSQR)):
        return

    # --- Get source & destination IP safely (IPv4 or IPv6) ---
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    else:
        # No IP layer present → ignore this packet
        return

    # --- Extract and clean domain name safely ---
    qname = packet[DNSQR].qname
    if isinstance(qname, bytes):
        domain = qname.decode("utf-8", errors="ignore").rstrip(".")
    else:
        domain = str(qname).rstrip(".")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] DNS Query: {domain} from {src_ip} → {dst_ip}")

    # --- Send to backend, including dst_ip now ---
    try:
        requests.post(
            INGEST_URL,
            json={
                "domain": domain,
                "src_ip": src_ip,
                "dst_ip": dst_ip,      # 👈 ADDED
                "timestamp": timestamp,
            },
            timeout=2,
        )
    except Exception as e:
        print("Ingest error:", e)


def main():
    print("🚀 Starting DNS packet capture...")
    print("Listening for DNS queries on udp port 53 ...")
    sniff(filter="udp port 53", prn=process_packet, store=0)


if __name__ == "__main__":
    main()
