import sys
import socket
import random
import time

# Check for target IP input
if len(sys.argv) < 2:
    print("Usage: python3 laptop2_attacker.py <target_ip>")
    sys.exit(1)

target_ip = sys.argv[1]
target_port = 80  # Example port for HTTP requests

# Generate a mix of malicious and good requests
def generate_requests():
    malicious_count = 0
    while True:
        try:
            # Create a TCP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)

            # Generate random behavior
            if random.random() > 0.5:
                # Malicious request
                s.connect((target_ip, target_port))
                s.send(b"MALICIOUS_PACKET")
                print(f"\033[91m[ATTACK] Sent malicious packet to {target_ip}\033[0m")
                malicious_count += 1
            else:
                # Good request
                s.connect((target_ip, target_port))
                s.send(b"GOOD_PACKET")
                print(f"\033[92m[INFO] Sent good packet to {target_ip}\033[0m")

            s.close()

            # Pause between requests
            time.sleep(0.1)

            # Stop after sending 300 malicious packets for testing
            if malicious_count >= 300:
                print("Reached limit of 300 malicious packets. Stopping...")
                break

        except Exception as e:
            print(f"Error: {e}")
            break

if __name__ == "__main__":
    generate_requests()
