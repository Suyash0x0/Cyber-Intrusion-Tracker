import sys
from scapy.all import sniff
import subprocess
import requests
import time
from collections import defaultdict
from geoip2 import database
import pyfiglet

# Display project introduction
intro_text = pyfiglet.figlet_format("CYBER INTRUSION TRACKER", font="slant")
print(intro_text)
print("Project by Suyash Kharate\n")

# Check for IP address input
if len(sys.argv) < 2:
    print("Usage: python3 enhanced_ids.py <target_ip>")
    sys.exit(1)

target_ip = sys.argv[1]

# Configuration
MAX_PACKETS = 50  # Packet threshold per IP within TIME_WINDOW
TIME_WINDOW = 10  # Time window for packet threshold in seconds
THREAT_FEED_URL = "https://example-threat-feed.com/api/malicious-ips"  # Replace with actual feed
GEO_DB_PATH = "GeoLite2-City.mmdb"  # Path to GeoIP database

# Data structures for logging and blocking
packet_counts = defaultdict(int)
block_list = defaultdict(lambda: None)
log_file = "malicious_ip_log.txt"

# Function to block IP with IPtables
def block_ip(ip):
    print(f"[ALERT] Blocking IP: {ip}")
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    block_list[ip] = time.time()
    log_ip(ip, "Blocked")

# Function to unblock IP after timeout
def unblock_ips():
    for ip, block_time in list(block_list.items()):
        if time.time() - block_time > TIME_WINDOW * 2:
            print(f"[INFO] Unblocking IP: {ip}")
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            del block_list[ip]

# Log IP with timestamp
def log_ip(ip, action):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    with open(log_file, "a") as f:
        f.write(f"{timestamp} - {ip} - {action}\n")

# Geo-location lookup
def get_geo_location(ip):
    try:
        with database.Reader(GEO_DB_PATH) as reader:
            response = reader.city(ip)
            return f"{response.country.name}, {response.city.name}"
    except:
        return "Unknown"

# Threat intelligence update
def update_threat_list():
    try:
        response = requests.get(THREAT_FEED_URL)
        for ip in response.json().get("malicious_ips", []):
            block_ip(ip)
    except Exception as e:
        print(f"Failed to update threat list: {e}")

# Analyze each packet for malicious activity
def analyze_packet(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        packet_counts[src_ip] += 1

        # Color-coded output for each request
        if packet_counts[src_ip] > MAX_PACKETS:
            location = get_geo_location(src_ip)
            print(f"[ALERT] Malicious IP detected: {src_ip} (Location: {location})")
            log_ip(src_ip, "Detected")
            block_ip(src_ip)
        else:
            print(f"[INFO] Incoming request from {src_ip} (Packet count: {packet_counts[src_ip]})")

# Reset packet counts
def reset_packet_counts():
    global packet_counts
    packet_counts = defaultdict(int)

# Main IDS function
def start_ids():
    last_reset = time.time()
    last_update = time.time()

    print(f"Starting IDS on target IP {target_ip}...")

    while True:
        sniff(prn=analyze_packet, count=1, timeout=1)
        unblock_ips()

        if time.time() - last_reset > TIME_WINDOW:
            reset_packet_counts()
            last_reset = time.time()

        if time.time() - last_update > TIME_WINDOW * 5:
            update_threat_list()
            last_update = time.time()

if __name__ == "__main__":
    start_ids()
