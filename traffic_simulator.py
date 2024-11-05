import sys
import time
import random
from scapy.all import send, IP, TCP
import pyfiglet

# Display project introduction
intro_text = pyfiglet.figlet_format("CYBER INTRUSION TRACKER", font="slant")
print(intro_text)
print("Project by Suyash Kharate\n")

# Check for IP address input
if len(sys.argv) < 2:
    print("Usage: python3 traffic_simulator.py <target_ip>")
    sys.exit(1)

target_ip = sys.argv[1]

# Configuration for traffic simulation
NORMAL_TRAFFIC_INTERVAL = 2  # Interval in seconds between normal requests
MALICIOUS_TRAFFIC_INTERVAL = 10  # Interval in seconds between malicious bursts
MALICIOUS_BURST_SIZE = 20  # Number of packets sent in each malicious burst

# Function to generate a random IP address
def generate_random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

# Function to send normal traffic
def send_normal_traffic():
    packet = IP(dst=target_ip) / TCP(dport=80)  # Adjust the destination port as needed
    send(packet, verbose=False)
    print(f"[INFO] Sent normal request to {target_ip}")

# Function to send malicious traffic from random IPs
def send_malicious_traffic():
    for _ in range(MALICIOUS_BURST_SIZE):
        spoofed_ip = generate_random_ip()
        packet = IP(src=spoofed_ip, dst=target_ip) / TCP(dport=80)
        send(packet, verbose=False)
        print(f"[ALERT] Sent malicious request from {spoofed_ip} to {target_ip}")
        time.sleep(0.1)  # Slight delay between malicious packets

# Main traffic simulation function
def simulate_traffic():
    last_malicious_time = time.time()

    while True:
        # Send normal traffic at regular intervals
        send_normal_traffic()
        time.sleep(NORMAL_TRAFFIC_INTERVAL)

        # Periodically send bursts of malicious traffic
        if time.time() - last_malicious_time > MALICIOUS_TRAFFIC_INTERVAL:
            print(f"[ALERT] Sending malicious traffic burst from random IPs...")
            send_malicious_traffic()
            last_malicious_time = time.time()

if __name__ == "__main__":
    print(f"Starting traffic simulation on target IP {target_ip} with mixed normal and malicious requests...")
    simulate_traffic()
