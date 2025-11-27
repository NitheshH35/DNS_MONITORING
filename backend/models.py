# backend/monitor.py
from scapy.all import sniff, DNS, DNSQR, IP, IPv6, UDP
from datetime import datetime
import requests
import sys
import os

INGEST_URL = "http://127.0.0.1:5000/ingest"

def safe_decode_qname(qname):
    if qname is None:
        return ""
    if isinstance(qname, bytes):
        try:
            return qname.decode("utf-8", errors="ignore").rstrip(".")
        except:
            return str(qname).rstrip(".")
    return str(qname).rstrip(".")

def process_packet(packet):
    # Only DNS queries (UDP dst port 53 or UDP src port 53?) — we want queries, so qr==0
    try:
        if not (packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 and packet.haslayer(DNSQR)):
            return

        # src ip (IPv4 or IPv6)
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            return

        # get queried domain
        qname = packet[DNSQR].qname
        domain = safe_decode_qname(qname)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"[{timestamp}] DNS Query: {domain} from {src_ip} -> resolver {dst_ip}")

        # send to backend ingest endpoint
        try:
            requests.post(
                INGEST_URL,
                json={"domain": domain, "src_ip": src_ip, "dst_ip": dst_ip, "timestamp": timestamp},
                timeout=2
            )
        except Exception as e:
            # backend might be down; print and continue
            print("Ingest error:", e)
    except Exception as e:
        print("process_packet error:", e)

def main():
    if os.name == 'nt':
        print("Warning: On Windows you may need to run this script as Administrator.")
    print("🚀 Starting DNS packet capture...")
    print("Listening for DNS queries on udp port 53 ... (requires privileges)")
    # sniff only UDP port 53
    sniff(filter="udp port 53", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
