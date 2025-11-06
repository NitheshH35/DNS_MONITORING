from scapy.all import sniff, DNS, DNSQR
import sqlite3
from datetime import datetime

DB_PATH = "database.db"

def log_dns_query(domain, src_ip, timestamp):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO dns_logs (domain, src_ip, timestamp) VALUES (?, ?, ?)", (domain, src_ip, timestamp))
    conn.commit()
    conn.close()

def process_packet(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # DNS query
        domain = packet[DNSQR].qname.decode("utf-8")
        src_ip = packet[1].src
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] DNS Query: {domain} from {src_ip}")
        log_dns_query(domain, src_ip, timestamp)

def main():
    print("🚀 Starting DNS packet capture...")
    print("Listening for DNS queries...")
    sniff(filter="udp port 53", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
