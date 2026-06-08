# PESZARA XDR Telemetry Agent

A lightweight host monitoring agent written in Python. It captures running processes, active connection sockets, file system events, and CPU/memory specifications, and ships them to the PESZARA XDR backend.

## Requirements

1. **Python 3.8+**
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Execution

1. Start the agent:
   ```bash
   python agent.py
   ```
2. The agent automatically generates a unique Device ID from your MAC address and establishes connection telemetry updates in a 10-second loop.

## Threat Detection & File Watcher Testing
* To simulate file modifications (e.g. autostart modifications, ransomware encryption), write or create files in the auto-generated directory `./watch_folder/` (e.g. rename a file to `test.locked`). The agent will immediately register the creation/modification and report it to the backend.
