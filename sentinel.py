import socket
import threading
from collections import defaultdict
import time
import platform
import subprocess
import sys
from datetime import datetime

PROTECTED_PORT = 80
MAX_CONNECTIONS_PER_IP = 50  
TIME_WINDOW = 60
BAN_TIME = 3600  

connection_counts = defaultdict(int)
banned_ips = set()
last_reset_time = time.time()

def log_message(message):
    """Log messages with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def reset_connection_counts():
    """Periodically reset connection counts"""
    global last_reset_time
    while True:
        time.sleep(TIME_WINDOW)
        connection_counts.clear()
        last_reset_time = time.time()
        log_message("Connection counts reset")

def block_ip(ip_address):
    """Block an IP address using system firewall"""
    banned_ips.add(ip_address)
    log_message(f"Blocking IP: {ip_address}")
    
    try:
        if platform.system() == "Linux":
            # For Linux 
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        elif platform.system() == "Windows":
            # For Windows 
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", 
                          f"name=\"Block {ip_address}\"", "dir=in", "action=block", 
                          f"remoteip={ip_address}"], check=True)
        elif platform.system() == "Darwin":
            # For macOS 
            subprocess.run(["echo", f"block in from {ip_address} to any | pfctl -a custom -f -"], shell=True)
    except subprocess.CalledProcessError as e:
        log_message(f"Failed to block IP {ip_address}: {e}")

def handle_client(client_socket, client_address):
    """Handle incoming client connections"""
    global connection_counts
    
    ip = client_address[0]
    
    if ip in banned_ips:
        client_socket.close()
        return
    
    connection_counts[ip] += 1
    
    if connection_counts[ip] > MAX_CONNECTIONS_PER_IP:
        log_message(f"Potential DoS attack detected from {ip} ({connection_counts[ip]} connections)")
        block_ip(ip)
        client_socket.close()
        return
    
    try:
        request = client_socket.recv(1024)
        if request:
          
            response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome</body></html>"
            client_socket.send(response)
    except Exception as e:
        log_message(f"Error handling client {ip}: {e}")
    finally:
        client_socket.close()

def start_protection_server():
    """Start the protection server"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PROTECTED_PORT))
    server.listen(100)
    log_message(f"Protection server started on port {PROTECTED_PORT}")
    
    
    threading.Thread(target=reset_connection_counts, daemon=True).start()
    
    while True:
        try:
            client_socket, client_address = server.accept()
            threading.Thread(target=handle_client, args=(client_socket, client_address)).start()
        except Exception as e:
            log_message(f"Server error: {e}")

if __name__ == "__main__":
    log_message("Starting DoS protection system")
    start_protection_server()
