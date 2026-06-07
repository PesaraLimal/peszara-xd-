# PESZARA XDR

### AI-Powered Endpoint Security, Threat Detection & Investigation Platform

> 🚀 **Deploying to Production?** Check out the step-by-step [Solo-Developer Deployment Guide](file:///C:/Users/CYBORG/Desktop/SOC/DEPLOYMENT.md) to launch your live demo on Vercel, Render, and Neon.

PESZARA XDR is a single-tenant Endpoint Detection and Response (EDR) platform designed for home or lab monitoring. It collects process trees and network connection telemetry in real-time, matches system behaviors against custom heuristic rules mapped to the **MITRE ATT&CK** framework, queries Threat Intelligence indicators, and leverages an **AI Copilot** (via OpenAI or local Ollama) to draft response playbooks and investigate alerts.

---

## System Architecture

```
                      +-----------------------------+
                      |   Target Machine (Endpoint) |
                      |   Python Telemetry Agent    |
                      +--------------+--------------+
                                     |
                                     | (HTTPS Ingestion Telemetry)
                                     v
                      +--------------+--------------+
                      |       FastAPI Backend       | <----+ Threat Intel
                      |       (Uvicorn Engine)      |      | (VirusTotal / AbuseIPDB)
                      +-------+--------------+------+
                              |              |
           (Store/Query Logs) |              | (AI Prompts)
                              v              v
                      +-------+------+   +---+------+
                      |  PostgreSQL  |   | OpenAI / |
                      |   Database   |   |  Ollama  |
                      +-------+------+   +----------+
                              ^
                              | (Isolated Queries by device_id)
                      +-------+------+
                      |   Next.js    |
                      | Web Frontend |
                      +--------------+
```

---

## Repository Structure

```
peszara-xdr/
├── docker-compose.yml     # Multi-container orchestration
├── .env                   # Configuration credentials
├── README.md
├── backend/               # FastAPI core engine
│   ├── app/
│   │   ├── main.py        # Bootstrapper
│   │   ├── database.py    # Database connection management
│   │   ├── models.py      # SQLAlchemy schemas
│   │   ├── schemas.py     # Pydantic serialization
│   │   ├── detection/     # Heuristics & MITRE mappings
│   │   ├── intel/         # VT & AbuseIPDB client connections
│   │   └── ai/            # GPT-4o-mini & Ollama Llama3 client
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/              # Next.js & Tailwind Web console
│   ├── src/
│   │   └── app/           # App-router layout, pages, and detail dashboards
│   ├── package.json
│   └── Dockerfile
└── agent/                 # Telemetry collection agent
    ├── agent.py           # Monitoring script (psutil)
    └── requirements.txt
```

---

## Quick Start & Installation

### Prerequisite
- [Docker & Docker Compose](https://www.docker.com/) Installed
- Python 3.10+ (for the Telemetry Agent)

### Step 1: Clone and Configure Environment
Copy `.env.example` to `.env` and configure optional keys:
```bash
cp .env.example .env
```
*Note: If API keys are left blank, PESZARA XDR will run in simulation mode with mock lookups to ensure the system is fully functional.*

### Step 2: Build & Start XDR Servers
Start the database, backend, and frontend containers in the background:
```bash
docker-compose up --build -d
```
Verify the health check of the backend by visiting `http://localhost:8000/api/v1/health`.
The Next.js Web Console will be active at `http://localhost:3000`.

### Step 3: Run the Telemetry Agent
On the host or virtual machine you want to monitor, execute the telemetry agent:
```bash
cd agent
pip install -r requirements.txt

# Run the agent (requires python 3)
python agent.py
```
The agent automatically generates a unique Device ID in `device_id.txt` (e.g. `DESKTOP-5D2D3E4F`) and uploads system states to the dashboard every 10 seconds.

---

## Threat Simulation & Verification (Portfolio Demo)

To verify threat detection rules and demonstrate XDR capabilities, execute the following commands on the agent-monitored host:

### 1. Simulate PowerShell Defense Evasion (Execution & Defense Evasion)
Execute an encoded or bypass command block in PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "Write-Output 'Simulated Threat Activity'"
```
- **XDR Alert Triggered**: *Suspicious PowerShell Execution*
- **MITRE Mapping**: T1059.001 (PowerShell)

### 2. Simulate Command-and-Control Connection (C2 Non-Standard Port)
Run a script or attempt to connect to a typical Metasploit port:
```bash
# Windows Command Prompt / PowerShell
powershell -Command "New-Object System.Net.Sockets.TcpClient('185.112.145.2', 4444)"
```
- **XDR Alert Triggered**: *Connection to Malicious IP & Suspicious Port Connection Attempt*
- **MITRE Mapping**: T1071 (Application Layer Protocol) & T1095 (Non-Application Layer Protocol)
- **Threat Intel enrichment**: AbuseIPDB flags `185.112.145.2` as malicious C2.

### 3. Simulate Privilege Reconnaissance (Discovery)
Check privileges and user groups:
```bash
whoami /priv
```
- **XDR Alert Triggered**: *System Privilege Enumeration*
- **MITRE Mapping**: T1033 (System Owner/User Discovery)

### 4. AI Investigation Audit
1. Open `http://localhost:3000` and select your active monitored host.
2. In the right-hand panel, select the **Suspicious PowerShell Execution** or **Connection to Malicious IP** alert.
3. Click **RUN AI AUDIT**.
4. The AI Investigation Copilot will generate a plain-English incident breakdown, map the attack flow, and write containment playbooks.
5. Click **EXPORT REPORT** to download a flat-text incident report.
