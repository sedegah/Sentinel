# Sentinel

**Sentinel** is a lightweight real-time server protection tool designed to detect and mitigate potential Denial-of-Service (DoS) attacks based on connection frequency. It actively monitors incoming connections and dynamically blocks suspicious IP addresses using system-level firewall rules.

## Features

- Real-time detection of high-frequency connection attempts
- Automatic banning of abusive IPs using system firewall
- Periodic reset of connection counters
- Cross-platform support (Linux, Windows, macOS)
- Configurable thresholds and ban durations
- Simple logging with timestamps

## How It Works

Sentinel tracks the number of incoming connections from each IP address over a fixed time window. If a single IP exceeds the allowed number of connections within this window, it is automatically blocked using the appropriate firewall rule for the operating system.

## Configuration

You can adjust the following parameters in the script:

```python
PROTECTED_PORT = 80            
MAX_CONNECTIONS_PER_IP = 50     
TIME_WINDOW = 60                
BAN_TIME = 3600                 
````

## Supported Platforms

* **Linux**: Uses `iptables`
* **Windows**: Uses `netsh advfirewall`
* **macOS**: Uses `pfctl`

> Note: macOS support is experimental and may require additional privileges.

## Usage

1. Ensure Python 3 is installed.
2. Run the script with administrator/root privileges:

```bash
sudo python3 sentinel.py
```

3. The tool will start listening on the specified port and monitoring for abusive traffic.

## Disclaimer

Sentinel is intended for educational and defensive use only. Unauthorized use of this tool against systems you do not own or operate is strictly prohibited.

