import socket
import time

def send_request(target_ip, target_port, protocol):
    try:
        if protocol.lower() == "smtp":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target_ip, target_port))
                s.sendall(b"EHLO example.com\r\n")
                time.sleep(0.5)
        elif protocol.lower() == "ftp":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target_ip, target_port))
                s.sendall(b"USER anonymous\r\nPASS anonymous\r\n")
                time.sleep(0.5)
        elif protocol.lower() == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(b"Hello, this is a UDP message!", (target_ip, target_port))
                time.sleep(0.5)
        elif protocol.lower() == "gopher":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target_ip, target_port))
                s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                time.sleep(0.5)
    except socket.error as e:
        print(f"Error sending {protocol.upper()} request: {e}")

def generate_requests(target_ip):
    protocol = input("Choose the protocol to send requests (SMTP, FTP, UDP, Gopher): ").strip()
    port_mapping = {"smtp": 25, "ftp": 21, "udp": 53, "gopher": 70}
    if protocol.lower() not in port_mapping:
        print("Invalid protocol choice. Exiting.")
        return
    
    target_port = port_mapping[protocol.lower()]
    print(f"Sending {protocol.upper()} requests to {target_ip}:{target_port}...")

    good_count, bad_count = 2, 2  # Initial good and bad request counts

    while True:
        print(f"Sending {good_count} good requests...")
        for _ in range(good_count):
            send_request(target_ip, target_port, protocol)

        print(f"Sending {bad_count} malicious requests...")
        for _ in range(bad_count):
            send_request(target_ip, target_port, protocol)  # Simulate malicious requests

        good_count *= 2  # Double the number of good requests
        bad_count *= 2  # Double the number of malicious requests
        time.sleep(2)

if __name__ == "__main__":
    target_ip = input("Enter the target IP address (Laptop 1): ").strip()
    generate_requests(target_ip)
