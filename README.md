# Intrusion Detection System (IDS) Project

This project is an Intrusion Detection System (IDS) that monitors network traffic, identifies malicious requests, and blocks the IPs of these requests. It’s built to demonstrate real-time detection with IP blocking, logging, and geolocation features.

## Features

- **Monitors Network Traffic**: Detects incoming requests.
- **Identifies Malicious IPs**: Uses a configurable threshold to flag IPs as malicious.
- **Blocks Malicious IPs**: Automatically blocks IPs exceeding the request threshold.
- **IP Logging**: Logs each detected malicious IP with a timestamp.
- **Geolocation of IPs**: Uses a GeoIP database to display location information for detected IPs.

## Project Structure

- `enhanced_ids.py`: The IDS script to be run on Laptop 1.
- `traffic_simulator.py`: Traffic generator script to simulate both normal and malicious traffic on Laptop 2.
- `requirements.txt`: Dependencies for the project.
- `GeoLite2-City.mmdb`: GeoIP database file (download required).

## Prerequisites

- **Python 3.x**
- **Scapy**: `pip install scapy`
- **GeoIP Database**: [Download the GeoLite2 City database](https://dev.maxmind.com/geoip/geoip2/geolite2/) and place it in the project directory as `GeoLite2-City.mmdb`.

## Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/yourusername/IDS-Project.git
    cd IDS-Project
    ```

2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Download and add the `GeoLite2-City.mmdb` file to the project directory for geolocation support.

## Usage

### 1. Run the IDS on Laptop 1

```bash
sudo python3 enhanced_ids.py <your-laptop-ip>
```

### 2. Run the Traffic Generator on Laptop 2

Replace `<target-ip>` with the IP address of Laptop 1.

```bash
python3 traffic_simulator.py <target-ip>
```

The IDS will monitor incoming traffic, marking malicious IPs in red and logging their geolocation.

## License

MIT License
