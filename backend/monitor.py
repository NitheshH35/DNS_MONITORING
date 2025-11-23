# backend/monitor.py
from scapy.all import sniff, DNS, DNSQR, IP
from datetime import datetime
import requests

INGEST_URL = "http://127.0.0.1:5000/ingest"

def process_packet(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        domain = packet[DNSQR].qname.decode("utf-8")
        src_ip = packet[IP].src
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] DNS Query: {domain} from {src_ip}")
        try:
            requests.post(INGEST_URL, json={"domain": domain, "src_ip": src_ip, "timestamp": timestamp}, timeout=2)
        except Exception as e:
            print("Ingest error:", e)

def main():
    print("🚀 Starting DNS packet capture...")
    print("Listening for DNS queries...")
    sniff(filter="udp port 53", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
