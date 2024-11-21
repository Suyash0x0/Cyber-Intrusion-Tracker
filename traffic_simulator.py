import sys
import random
import time
from scapy.all import IP, TCP, UDP, send
import pyfiglet

# Display project introduction
intro_text = pyfiglet.figlet_format("CYBER INTRUSION TRACKER", font="slant")
print(intro_text)
print("Request Generator by Suyash Kharate\n")

# Check for IP address input
if len(sys.argv) < 2:
    print("Usage: python3 request_generator.py <target_ip>")
    sys.exit(1)

target_ip = sys.argv[1]

# Protocol-specific ports
PROTOCOL_PORTS = {
    "SMTP": 25,
    "FTP": 21,
    "Gopher": 70,
    "UDP": 53,  # Default to DNS traffic for demonstration
}

# Generate SMTP traffic
def generate_smtp():
    print("[INFO] Generating SMTP requests...")
    for _ in range(10):  # Number of packets
        pkt = IP(dst=target_ip) / TCP(dport=PROTOCOL_PORTS["SMTP"], flags="S")
        send(pkt, verbose=False)
        time.sleep(0.5)

# Generate FTP traffic
def generate_ftp():
    print("[INFO] Generating FTP requests...")
    for _ in range(10):  # Number of packets
        pkt = IP(dst=target_ip) / TCP(dport=PROTOCOL_PORTS["FTP"], flags="S")
        send(pkt, verbose=False)
        time.sleep(0.5)

# Generate Gopher traffic
def generate_gopher():
    print("[INFO] Generating Gopher requests...")
    for _ in range(10):  # Number of packets
        pkt = IP(dst=target_ip) / TCP(dport=PROTOCOL_PORTS["Gopher"], flags="S")
        send(pkt, verbose=False)
        time.sleep(0.5)

# Generate UDP traffic
def generate_udp():
    print("[INFO] Generating UDP requests...")
    for _ in range(10):  # Number of packets
        pkt = IP(dst=target_ip) / UDP(dport=PROTOCOL_PORTS["UDP"])
        send(pkt, verbose=False)
        time.sleep(0.5)

# Menu for traffic generation
def menu():
    print("\nChoose the type of traffic to generate:")
    print("1. SMTP (Port 25)")
    print("2. FTP (Port 21)")
    print("3. Gopher (Port 70)")
    print("4. UDP (Port 53)")
    print("5. Exit")

    while True:
        choice = input("\nEnter your choice (1-5): ")
        if choice == "1":
            generate_smtp()
        elif choice == "2":
            generate_ftp()
        elif choice == "3":
            generate_gopher()
        elif choice == "4":
            generate_udp()
        elif choice == "5":
            print("[INFO] Exiting the request generator.")
            break
        else:
            print("[WARNING] Invalid choice. Please select a valid option.")

# Main function
if __name__ == "__main__":
    print(f"[INFO] Target IP: {target_ip}")
    menu()
