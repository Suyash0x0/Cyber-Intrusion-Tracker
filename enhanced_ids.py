import sys
import threading
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
MAX_PACKETS = 20  # Block IP after 20 packets in TIME_WINDOW
TIME_WINDOW = 10  # Time window for packet threshold in seconds
BLOCK_DURATION = 60  # Block duration for automatic unblocking in seconds
THREAT_FEED_URL = "https://example-threat-feed.com/api/malicious-ips"  # Replace with actual feed
GEO_DB_PATH = "GeoLite2-City.mmdb"  # Path to GeoIP database
PROTOCOL_PORTS = {"SMTP": 25, "FTP": 21, "Gopher": 70}

# Data structures for logging and blocking
packet_counts = defaultdict(int)
block_list = defaultdict(lambda: None)
log_file = "malicious_ip_log.txt"

# Function to block IP with IPtables
def block_ip(ip):
    if ip not in block_list:
        print(f"\033[91m[ALERT] Blocking IP: {ip}\033[0m")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        block_list[ip] = time.time()
        log_ip(ip, "Blocked")
    else:
        print(f"\033[93m[INFO] IP {ip} is already blocked.\033[0m")

# Function to unblock IP after timeout
def unblock_ips():
    for ip, block_time in list(block_list.items()):
        if time.time() - block_time > BLOCK_DURATION:
            print(f"\033[92m[INFO] Automatically unblocking IP: {ip}\033[0m")
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            del block_list[ip]

# Function to manually unblock an IP
def manual_unblock(ip):
    if ip in block_list:
        print(f"\033[92m[INFO] Manually unblocking IP: {ip}\033[0m")
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        del block_list[ip]
        log_ip(ip, "Manually Unblocked")
    else:
        print(f"\033[93m[INFO] IP {ip} is not in the blocklist.\033[0m")

# Function to show currently blocked IPs
def show_blocklist():
    if block_list:
        print("\033[96m[INFO] Currently Blocked IPs:\033[0m")
        for ip in block_list.keys():
            print(f"  - {ip}")
    else:
        print("\033[96m[INFO] No IPs are currently blocked.\033[0m")

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

        # Check for UDP traffic
        if packet.haslayer("UDP"):
            print(f"\033[94m[INFO] UDP request detected from {src_ip}\033[0m")
            log_ip(src_ip, "UDP Request")

        # Check for specific protocols using ports
        if packet.haslayer("TCP"):
            tcp_layer = packet["TCP"]
            if tcp_layer.dport in PROTOCOL_PORTS.values():
                protocol_name = [name for name, port in PROTOCOL_PORTS.items() if port == tcp_layer.dport][0]
                print(f"\033[95m[INFO] {protocol_name} traffic detected from {src_ip}\033[0m")
                log_ip(src_ip, f"{protocol_name} Traffic")

        # Detect malicious activity based on packet count
        if packet_counts[src_ip] > MAX_PACKETS:
            location = get_geo_location(src_ip)
            print(f"\033[91m[ALERT] Malicious IP detected: {src_ip} (Location: {location})\033[0m")
            log_ip(src_ip, "Detected")
            block_ip(src_ip)
        else:
            print(f"\033[94m[INFO] Incoming request from {src_ip} (Packet count: {packet_counts[src_ip]})\033[0m")

# Reset packet counts
def reset_packet_counts():
    global packet_counts
    packet_counts = defaultdict(int)

# Function to handle user commands in a separate thread
def command_listener():
    while True:
        command = input("Enter a command: ").strip()
        if command == "show blocklist":
            show_blocklist()
        elif command.startswith("unblock"):
            try:
                _, ip = command.split()
                manual_unblock(ip)
            except ValueError:
                print("\033[91m[ERROR] Invalid command format. Use: unblock <IP>\033[0m")
        else:
            print("\033[91m[ERROR] Unknown command. Available commands:\033[0m")
            print("  - show blocklist")
            print("  - unblock <IP>")

# Main IDS function
def start_ids():
    last_reset = time.time()
    last_update = time.time()

    print(f"Starting IDS on target IP {target_ip}...\n")
    print("Commands:")
    print("  - Type 'show blocklist' to display blocked IPs")
    print("  - Type 'unblock <IP>' to manually unblock an IP")
    print("  - Press CTRL+C to stop the IDS\n")

    # Start the command listener in a separate thread
    threading.Thread(target=command_listener, daemon=True).start()

    try:
        while True:
            sniff(prn=analyze_packet, count=1, timeout=1)
            unblock_ips()  # Automatically unblock IPs

            if time.time() - last_reset > TIME_WINDOW:
                reset_packet_counts()
                last_reset = time.time()

            if time.time() - last_update > TIME_WINDOW * 5:
                update_threat_list()
                last_update = time.time()

    except KeyboardInterrupt:
        print("\033[93m[INFO] Stopping Cyber Intrusion Tracker...\033[0m")

if __name__ == "__main__":
    start_ids()
