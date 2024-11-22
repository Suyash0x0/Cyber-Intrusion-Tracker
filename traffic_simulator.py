import sys
import socket
import time
import random
import pyfiglet

# Display project introduction
intro_text = pyfiglet.figlet_format("CYBER INTRUSION ATTACKER", font="slant")
print(intro_text)
print("Project by Suyash Kharate\n")

# Check for IP address input
if len(sys.argv) < 2:
    print("Usage: python3 attacker_script.py <target_ip>")
    sys.exit(1)

target_ip = sys.argv[1]
target_port = 80  # Default port for HTTP; adjust based on testing needs

# Protocol-specific payloads
payloads = {
    "SMTP": "MAIL FROM: <attacker@domain.com>\r\nRCPT TO: <victim@domain.com>\r\nDATA\r\nTest SMTP request.\r\n.\r\n",
    "FTP": "USER attacker\r\nPASS password\r\nLIST\r\n",
    "UDP": "Random UDP data",
    "Gopher": "GET / HTTP/1.0\r\n\r\n",
    "HTTP": "GET /index.html HTTP/1.1\r\nHost: {}\r\n\r\n".format(target_ip),
}

# Function to send traffic
def send_request(protocol, target_ip, target_port):
    try:
        if protocol == "UDP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(payloads[protocol].encode(), (target_ip, target_port))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, target_port))
            sock.send(payloads[protocol].encode())
        sock.close()
        print(f"Sent {protocol} request to {target_ip}")
    except Exception as e:
        print(f"Failed to send {protocol} request: {e}")

# Generate requests based on user choice
protocols = list(payloads.keys())
print("Available protocols:", ", ".join(protocols))

# Main loop
try:
    while True:
        # Pattern: 2 good, 2 malicious; then 4 good, 4 malicious; etc.
        for count in [2, 4, 8, 16, 32]:  # Expand this pattern as needed
            for _ in range(count):
                send_request(random.choice(["HTTP", "SMTP", "FTP"]), target_ip, target_port)  # Good requests
                time.sleep(0.5)
            for _ in range(count):
                send_request(random.choice(["UDP", "Gopher"]), target_ip, target_port)  # Malicious requests
                time.sleep(0.5)
except KeyboardInterrupt:
    print("\nStopping traffic generation...")
