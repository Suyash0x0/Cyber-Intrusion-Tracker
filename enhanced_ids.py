import sys
from scapy.all import sniff
import subprocess
import time
from collections import defaultdict
from geoip2 import database
import pyfiglet

# Display project introduction
intro_text = pyfiglet.figlet_format("CYBER INTRUSION TRACKER", font="slant")
print(intro_text)
print("Project by Suyash Kharate\n")

# Check for IP address input
if len(sys.argv) < 3:
    print("Usage: python3 defender_script.py <attacker_ip> <monitor_ip>")
    sys.exit(1)

attacker_ip = sys.argv[1]
monitor_ip = sys.argv[2]

# Configuration
MAX_MALICIOUS_PACKETS = 200
BLOCK_DURATION = 80  # Block duration in seconds
log_file = "malicious_traffic_log.txt"

# Data structures for tracking
packet_counts = defaultdict(int)
block_list = {}

# Function to log events
def log_event(ip, status):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"{timestamp} - {ip} - {status}\n")

# Function to block IP
def block_ip(ip):
    if ip not in block_list:
        print(f"\033[91m[ALERT] Blocking IP: {ip}\033[0m")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        block_list[ip] = time.time()
        log_event(ip, "Blocked")

# Function to unblock IP manually
def unblock_ip(ip):
    if ip in block_list:
        print(f"\033[92m[INFO] Unblocking IP: {ip}\033[0m")
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        del block_list[ip]
        log_event(ip, "Manually Unblocked")

# Function to automatically unblock IPs after timeout
def auto_unblock_ips():
    for ip, block_time in list(block_list.items()):
        if time.time() - block_time > BLOCK_DURATION:
            print(f"\033[92m[INFO] Automatically unblocking IP: {ip}\033[0m")
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            del block_list[ip]

# Analyze packets
def analyze_packet(packet):
    if packet.haslayer("IP") and packet["IP"].src == attacker_ip:
        src_ip = packet["IP"].src
        packet_counts[src_ip] += 1

        # Determine if request is malicious or good
        if packet.haslayer("UDP") or packet.haslayer("Raw") and b"Gopher" in packet["Raw"].load:
            print(f"\033[91m[ALERT] Malicious request from {src_ip}\033[0m")
            log_event(src_ip, "Malicious")
        else:
            print(f"\033[92m[INFO] Good request from {src_ip}\033[0m")
            log_event(src_ip, "Good")

        # Block if malicious threshold is exceeded
        if packet_counts[src_ip] >= MAX_MALICIOUS_PACKETS:
            block_ip(src_ip)

# Start IDS
def start_ids():
    print(f"Monitoring traffic from {attacker_ip} on {monitor_ip}...\n")
    try:
        sniff(filter=f"ip host {attacker_ip} and ip dst {monitor_ip}", prn=analyze_packet, store=False)
    except KeyboardInterrupt:
        print("\033[93m[INFO] Stopping IDS...\033[0m")

if __name__ == "__main__":
    start_ids()
