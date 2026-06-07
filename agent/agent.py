import os
import sys
import time
import socket
import platform
import hashlib
import uuid
import logging
import requests
import psutil
from datetime import datetime

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("PeszaraAgent")

import json

BACKEND_URL = os.getenv("PESZARA_BACKEND_URL", "http://localhost:8000")
SUBMIT_ENDPOINT = f"{BACKEND_URL}/api/v1/telemetry/submit"
INTERVAL_SECONDS = 10
REGISTRATION_KEY = os.getenv("PESZARA_REGISTRATION_KEY", "PESZARA_SECURE_REG_2026")

CONFIG_FILE = "device_config.json"
DEVICE_ID = None
DEVICE_TOKEN = None

def check_enrollment():
    global DEVICE_ID, DEVICE_TOKEN
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                DEVICE_ID = config.get("device_id")
                DEVICE_TOKEN = config.get("device_token")
                logger.info(f"Loaded config for enrolled Device ID: {DEVICE_ID}")
                return True
        except Exception as e:
            logger.error(f"Failed reading configuration file: {e}")
            
    logger.info("Configuration file not found. Requesting secure enrollment with backend...")
    
    reg_key = REGISTRATION_KEY
    if len(sys.argv) > 1:
        for idx, arg in enumerate(sys.argv):
            if arg == "--regkey" and idx + 1 < len(sys.argv):
                reg_key = sys.argv[idx + 1]
                
    register_url = f"{BACKEND_URL}/api/v1/devices/register"
    payload = {
        "hostname": socket.gethostname(),
        "os_name": platform.system(),
        "os_version": f"{platform.release()} ({platform.version()})",
        "ip_address": get_primary_ip(),
        "mac_address": get_mac_address(),
        "logged_in_user": get_logged_in_user(),
        "registration_key": reg_key
    }
    
    try:
        res = requests.post(register_url, json=payload, timeout=10)
        if res.status_code == 200:
            data = res.json()
            DEVICE_ID = data["device_id"]
            DEVICE_TOKEN = data["device_token"]
            
            with open(CONFIG_FILE, "w") as f:
                json.dump({
                    "device_id": DEVICE_ID,
                    "device_token": DEVICE_TOKEN
                }, f)
                
            from urllib.parse import urlparse
            parsed = urlparse(BACKEND_URL)
            host = parsed.hostname or "localhost"
            if "vercel.app" in host:
                dashboard_url = f"https://{host}{data['dashboard_url']}"
            else:
                dashboard_url = f"http://{host}:3000{data['dashboard_url']}"
            
            logger.info("=" * 80)
            logger.info("SECURE DEVICE ENROLLMENT SUCCESSFUL!")
            logger.info(f"Device ID: {DEVICE_ID}")
            logger.info(f"Device Access Token: {DEVICE_TOKEN[:6]}...")
            logger.info("YOUR UNIQUE PRIVATE SOC DASHBOARD URL:")
            logger.info(f"   {dashboard_url}   ")
            logger.info("=" * 80)
            return True
        else:
            logger.error(f"Backend enrollment rejected: {res.status_code} - {res.text}")
            logger.error("Please verify your registration key or check backend logs.")
            return False
    except Exception as e:
        logger.error(f"Failed to communicate with registration server: {e}")
        return False


def get_mac_address():
    try:
        mac = uuid.getnode()
        return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
    except Exception:
        return "00:00:00:00:00:00"


def get_primary_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def get_logged_in_user():
    try:
        users = psutil.users()
        if users:
            return users[0].name
    except Exception:
        pass
    
    # Fallbacks
    for var in ['USER', 'USERNAME', 'LOGNAME']:
        val = os.getenv(var)
        if val:
            return val
    return "Unknown"


def calculate_sha256(filepath):
    """Calculates the SHA256 hash of a file if readable."""
    if not filepath or not os.path.exists(filepath):
        return None
    try:
        # Don't hash huge files to avoid agent resource spikes
        if os.path.getsize(filepath) > 50 * 1024 * 1024:  # 50 MB
            return None
            
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def collect_telemetry():
    logger.info("Collecting telemetry data...")
    
    # System Info
    hostname = socket.gethostname()
    os_name = platform.system()
    os_version = f"{platform.release()} ({platform.version()})"
    ip_addr = get_primary_ip()
    mac_addr = get_mac_address()
    cpu_use = psutil.cpu_percent()
    ram_use = psutil.virtual_memory().percent
    current_user = get_logged_in_user()
    
    # Processes
    processes_payload = []
    # Fetch CPU percentages properly (first call might be zero, but continuous running is accurate)
    for p in psutil.process_iter(attrs=['pid', 'ppid', 'name', 'exe', 'cmdline', 'username']):
        try:
            info = p.info
            pid = info['pid']
            ppid = info['ppid']
            name = info['name'] or ""
            exe_path = info['exe'] or ""
            
            # Reconstruct command line string
            cmdline_list = info['cmdline']
            command_line = " ".join(cmdline_list) if cmdline_list else ""
            
            username = info['username'] or "SYSTEM"
            
            # Hash executable (only if it has an executable path)
            sha256_hash = calculate_sha256(exe_path) if exe_path else None
            
            # CPU and Memory measurements
            try:
                cpu_p = p.cpu_percent(interval=None)
                mem_p = p.memory_percent()
            except Exception:
                cpu_p = 0.0
                mem_p = 0.0
                
            processes_payload.append({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "exe_path": exe_path,
                "command_line": command_line,
                "username": username,
                "sha256_hash": sha256_hash,
                "cpu_percent": float(cpu_p),
                "memory_percent": float(mem_p)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Network Connections
    connections_payload = []
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            # Only report listening or established external connections
            if conn.status not in ['LISTEN', 'ESTABLISHED']:
                continue
                
            local_ip, local_port = conn.laddr if conn.laddr else ("0.0.0.0", 0)
            remote_ip, remote_port = conn.raddr if conn.raddr else ("0.0.0.0", 0)
            
            protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            
            connections_payload.append({
                "pid": conn.pid,
                "protocol": protocol,
                "local_address": local_ip,
                "local_port": local_port,
                "remote_address": remote_ip,
                "remote_port": remote_port,
                "state": conn.status
            })
    except Exception as e:
        logger.error(f"Error collecting net connections: {e}")

    payload = {
        "device_id": DEVICE_ID,
        "hostname": hostname,
        "os_name": os_name,
        "os_version": os_version,
        "ip_address": ip_addr,
        "mac_address": mac_addr,
        "cpu_usage": float(cpu_use),
        "ram_usage": float(ram_use),
        "logged_in_user": current_user,
        "processes": processes_payload,
        "network_connections": connections_payload
    }
    
    return payload


def main():
    logger.info("PESZARA XDR Telemetry Agent started.")
    logger.info(f"Targeting backend endpoint: {SUBMIT_ENDPOINT}")
    
    while not check_enrollment():
        logger.error("Enrollment failed. Retrying in 10 seconds...")
        time.sleep(10)
        
    while True:
        try:
            payload = collect_telemetry()
            logger.info(f"Submitting telemetry packet to backend. Processes: {len(payload['processes'])}, Connections: {len(payload['network_connections'])}")
            
            headers = {
                "X-Device-Id": DEVICE_ID,
                "X-Device-Token": DEVICE_TOKEN
            }
            
            response = requests.post(SUBMIT_ENDPOINT, json=payload, headers=headers, timeout=8)
            if response.status_code == 200:
                logger.info("Successfully uploaded telemetry packet.")
            else:
                logger.warning(f"Backend rejected telemetry: {response.status_code} - {response.text}")
        except requests.exceptions.RequestException as re:
            logger.error(f"Network error reporting to backend: {re}. Will retry.")
        except Exception as e:
            logger.error(f"Unexpected error in agent loop: {e}")
            
        logger.info(f"Sleeping for {INTERVAL_SECONDS} seconds...")
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Agent execution terminated by user.")
        sys.exit(0)
