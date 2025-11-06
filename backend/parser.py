# backend/parser.py
from scapy.all import *
from datetime import datetime
import sqlite3

def log_dns_packet(packet):
    if packet.haslayer(DNSQR):  # DNS Query
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        query_name = packet[DNSQR].qname.decode('utf-8')
        query_type = packet[DNSQR].qtype
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        response_ip = packet[IP].dst
        status = "Query"

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO dns_logs (timestamp, query_name, query_type, source_ip, destination_ip, response_ip, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, query_name, str(query_type), source_ip, destination_ip, response_ip, status))
        conn.commit()
        conn.close()
