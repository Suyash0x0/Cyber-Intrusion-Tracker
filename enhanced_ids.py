import sys
from scapy.all import sniff
import subprocess
import time
from collections import defaultdict
import pyfiglet

# Display project introduction
intro_text = pyfiglet.figlet_format("CYBER INTRUSION TRACKER", font="slant")
print(intro_text)
print("Project by Suyash Kharate\n")

# Check for input IP addresses
if len(sys.argv) < 3:
    print("Usage: python3 laptop1_ids.py <target_ip> <source_ip>")
    sys.exit(1)

target_ip = sys.argv[1]
source_ip = sys.argv[2]

# Configuration
MAX_MALICIOUS_PACKETS = 200  # Threshold for blocking
BLOCK_DURATION = 60  # Time to block an IP in seconds
packet_counts = defaultdict(int)  # Count packets per IP
block_list = defaultdict(lambda: None)  # Track blocked IPs
log_file = "malicious_ip_log.txt"

# Function to block an IP
def block_ip(ip):
    if ip not in block_list:
        print(f"\033[91m[ALERT] Blocking IP: {ip}\033[0m")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        block_list[ip] = time.time()
        log_ip(ip, "Blocked")
    else:
        print(f"\033[93m[INFO] IP {ip} is already blocked.\033[0m")

# Function to unblock IPs after timeout
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

# Log activity to a file
def log_ip(ip, action):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    with open(log_file, "a") as f:
        f.write(f"{timestamp} - {ip} - {action}\n")

# Analyze packets
def analyze_packet(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst

        # Only process packets between source and target IP
        if src_ip == source_ip and dst_ip == target_ip:
            packet_counts[src_ip] += 1

            # Detect malicious activity
            if packet_counts[src_ip] > MAX_MALICIOUS_PACKETS:
                print(f"\033[91m[ALERT] Detected 200+ malicious packets from {src_ip}\033[0m")
                log_ip(src_ip, "Malicious Traffic Detected")
                block_ip(src_ip)
            else:
                print(f"\033[94m[INFO] Packet {packet_counts[src_ip]} from {src_ip}\033[0m")
        else:
            print(f"\033[93m[INFO] Ignoring packet from {src_ip} to {dst_ip}\033[0m")

# Main IDS function
def start_ids():
    print(f"Monitoring traffic from {source_ip} to {target_ip}...\n")
    print("Commands:")
    print("  - Type 'unblock <IP>' to manually unblock an IP")
    print("  - Press CTRL+C to stop the IDS\n")

    try:
        while True:
            sniff(prn=analyze_packet, count=1, timeout=1)
            unblock_ips()

            # Check for manual commands
            command = input("Enter a command: ")
            if command.startswith("unblock"):
                _, ip = command.split()
                manual_unblock(ip)

    except KeyboardInterrupt:
        print("\033[93m[INFO] Stopping Cyber Intrusion Tracker...\033[0m")

if __name__ == "__main__":
    start_ids()
