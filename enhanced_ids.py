import sys
import threading
from scapy.all import sniff
import subprocess
import time
from collections import defaultdict
import pyfiglet

# Display project introduction
intro_text = pyfiglet.figlet_format("CYBER INTRUSION TRACKER", font="slant")
print(intro_text)
print("Project by Suyash Kharate\n")

# Check for IP address input
if len(sys.argv) < 3:
    print("Usage: python3 enhanced_ids.py <target_ip> <source_ip>")
    sys.exit(1)

target_ip = sys.argv[1]  # Laptop 1's IP
source_ip = sys.argv[2]  # Laptop 2's IP

# Configuration
MAX_PACKETS = 200  # Block IP after 200 packets in TIME_WINDOW
TIME_WINDOW = 10   # Time window for packet threshold in seconds
BLOCK_DURATION = 60  # Block duration for automatic unblocking in seconds

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

# Analyze each packet for malicious activity
def analyze_packet(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst

        # Monitor only requests from source_ip to target_ip
        if src_ip == source_ip and dst_ip == target_ip:
            packet_counts[src_ip] += 1

            print(f"\033[94m[INFO] Incoming request from {src_ip} to {dst_ip} (Packet count: {packet_counts[src_ip]})\033[0m")

            # Detect malicious activity based on packet count
            if packet_counts[src_ip] > MAX_PACKETS:
                print(f"\033[91m[ALERT] Malicious IP detected: {src_ip}\033[0m")
                log_ip(src_ip, "Detected")
                block_ip(src_ip)
        else:
            print(f"\033[93m[INFO] Ignoring packet: {src_ip} -> {dst_ip}\033[0m")

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

    print(f"Starting IDS to monitor traffic from {source_ip} to {target_ip}...\n")
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

    except KeyboardInterrupt:
        print("\033[93m[INFO] Stopping Cyber Intrusion Tracker...\033[0m")

if __name__ == "__main__":
    start_ids()
