import os
import sys
import time
import uuid
import socket
import platform
import hashlib
import requests
import psutil
from datetime import datetime
import threading

# Config
BACKEND_URL = os.getenv("PESZARA_BACKEND_URL", "http://localhost:8000/api/telemetry")
INTERVAL_SECONDS = 10
WATCH_DIR = os.path.join(os.getcwd(), "watch_folder")

# Create watch directory if it doesn't exist
if not os.path.exists(WATCH_DIR):
    os.makedirs(WATCH_DIR)
    print(f"[*] Created file telemetry watch folder: {WATCH_DIR}")

# Global list of queued file events
file_events_queue = []
file_events_lock = threading.Lock()

def get_device_id() -> str:
    """
    Generates a unique, persistent device ID based on the system's MAC address.
    """
    mac = uuid.getnode()
    # Format MAC or fallback
    mac_str = ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
    hasher = hashlib.sha256(mac_str.encode())
    return f"dev_{hasher.hexdigest()[:12]}"

def get_local_ip() -> str:
    """
    Helper to get the primary local IP address of the machine.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def calculate_sha256(filepath: str) -> str:
    """
    Calculates SHA256 hash of a file. Returns empty string if file is unreadable.
    """
    if not filepath or not os.path.exists(filepath):
        return ""
    try:
        # Ignore files over 20MB to prevent lag
        if os.path.getsize(filepath) > 20 * 1024 * 1024:
            return ""
        
        sha255 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha255.update(chunk)
        return sha255.hexdigest()
    except Exception:
        return ""

def watch_directory_loop():
    """
    Simple background thread to monitor the watch_folder for modifications/creations.
    """
    global file_events_queue
    print(f"[*] Monitoring directory for file activity: {WATCH_DIR}")
    
    # Store initial state: file -> last modified time
    last_state = {}
    try:
        for f in os.listdir(WATCH_DIR):
            path = os.path.join(WATCH_DIR, f)
            if os.path.isfile(path):
                last_state[path] = os.path.getmtime(path)
    except Exception as e:
        print(f"Error scanning watch dir: {e}")

    while True:
        try:
            time.sleep(2)
            current_state = {}
            files = []
            try:
                files = os.listdir(WATCH_DIR)
            except Exception:
                continue

            for f in files:
                path = os.path.join(WATCH_DIR, f)
                if os.path.isfile(path):
                    try:
                        current_state[path] = os.path.getmtime(path)
                    except Exception:
                        continue

            with file_events_lock:
                # Check for deletions
                for path in list(last_state.keys()):
                    if path not in current_state:
                        file_events_queue.append({
                            "action": "DELETED",
                            "filepath": path
                        })
                        print(f"[File Log] DELETED: {path}")

                # Check for creations and updates
                for path, mtime in current_state.items():
                    if path not in last_state:
                        file_events_queue.append({
                            "action": "CREATED",
                            "filepath": path
                        })
                        print(f"[File Log] CREATED: {path}")
                    elif mtime > last_state[path]:
                        file_events_queue.append({
                            "action": "MODIFIED",
                            "filepath": path
                        })
                        print(f"[File Log] MODIFIED: {path}")

            last_state = current_state
        except Exception as e:
            print(f"Watcher loop exception: {e}")

def gather_telemetry() -> dict:
    """
    Collects system, process, network, and file events telemetry.
    """
    global file_events_queue
    
    # System Info
    device_id = get_device_id()
    hostname = socket.gethostname()
    os_name = platform.system()
    os_version = platform.release()
    ip_address = get_local_ip()
    mac = uuid.getnode()
    mac_str = ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
    
    logged_in_user = ""
    try:
        users = psutil.users()
        if users:
            logged_in_user = users[0].name
        else:
            logged_in_user = os.getlogin()
    except Exception:
        # Fallback for Windows/headless setups
        logged_in_user = os.environ.get("USERNAME") or os.environ.get("USER") or "Unknown"

    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent

    # Gather Processes
    processes = []
    # Cache to map pid -> name for socket lookup
    pid_name_map = {}
    
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'username']):
        try:
            info = proc.info
            pid = info['pid']
            ppid = info['ppid']
            name = info['name'] or "unknown"
            exe = info['exe'] or ""
            username = info['username'] or ""
            
            # Map name for socket check
            pid_name_map[pid] = name

            # Only collect cmdline if needed, try/catch since cmdline might change or fail
            cmdline = ""
            try:
                cmdline = " ".join(proc.cmdline())
            except Exception:
                pass

            # Calculate SHA256 of the binary (optional, only if path exists and we have rights)
            sha256_hash = ""
            if exe and os.path.exists(exe):
                # Calculate hash for common shell, or process binaries
                if any(x in name.lower() for x in ["powershell", "cmd", "bash", "mimikatz", "nc", "python"]):
                    sha256_hash = calculate_sha256(exe)

            processes.append({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "exe": exe,
                "cmdline": cmdline,
                "username": username,
                "sha256": sha256_hash
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as e:
            print(f"Error reading process info: {e}")

    # Gather Connections (Sockets)
    connections = []
    try:
        net_conns = psutil.net_connections(kind='inet')
        for conn in net_conns:
            # Only keep active connections (ESTABLISHED, LISTEN, etc.)
            if conn.status in ["ESTABLISHED", "LISTEN"]:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                
                connections.append({
                    "pid": conn.pid,
                    "process_name": pid_name_map.get(conn.pid, "unknown") if conn.pid else "system",
                    "family": "IPv4" if conn.family == socket.AF_INET else "IPv6",
                    "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "laddr": laddr,
                    "raddr": raddr,
                    "status": conn.status
                })
    except Exception as e:
        print(f"Error gathering connections: {e}")

    # Pop file events from queue
    with file_events_lock:
        file_events = list(file_events_queue)
        file_events_queue.clear()

    return {
        "device_id": device_id,
        "hostname": hostname,
        "os_name": os_name,
        "os_version": os_version,
        "ip_address": ip_address,
        "mac_address": mac_str,
        "logged_in_user": logged_in_user,
        "cpu_usage": cpu_usage,
        "memory_usage": memory_usage,
        "processes": processes,
        "connections": connections,
        "file_events": file_events
    }

def main():
    print(f"=================================================")
    print(f"       PESZARA XDR ENDPOINT AGENT STARTED        ")
    print(f"=================================================")
    print(f"[*] Device ID:  {get_device_id()}")
    print(f"[*] Hostname:   {socket.gethostname()}")
    print(f"[*] Local IP:   {get_local_ip()}")
    print(f"[*] Target URL: {BACKEND_URL}")
    print(f"=================================================")

    # Start watcher thread
    watcher_thread = threading.Thread(target=watch_directory_loop, daemon=True)
    watcher_thread.start()

    while True:
        try:
            print(f"[*] Gathering host telemetry...")
            payload = gather_telemetry()
            
            print(f"[*] Sending telemetry ({len(payload['processes'])} processes, {len(payload['connections'])} sockets)...")
            response = requests.post(BACKEND_URL, json=payload, timeout=8)
            if response.status_code == 200:
                print(f"[+] Ingest response: {response.json()}")
            else:
                print(f"[!] Server returned error status: {response.status_code}")
        except requests.exceptions.ConnectionError:
            print(f"[!] Connection failed! PESZARA XDR Backend down at {BACKEND_URL}?")
        except Exception as e:
            print(f"[!] Telemetry shipping error: {e}")

        time.sleep(INTERVAL_SECONDS)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Agent stopped by user.")
        sys.exit(0)
