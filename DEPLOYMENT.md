# Solo-Developer Deployment Guide & Live Demo Architecture

This guide explains how to deploy **PESZARA XDR** as a fully live, production-like cybersecurity platform. Using this guide, a solo developer or undergraduate student can host the application on public cloud platforms (using free-tier resources) to create a portfolio-ready threat detection platform.

---

## 1. Live Demo System Flow

```
+---------------------------+
|    User Machine (Local)   |
|   Python Telemetry Agent  |
+-------------+-------------+
              |
              | (HTTPS Telemetry Packets /submit)
              v
+-------------+-------------+
|      FastAPI Backend      |
|     (Render / Railway)    |
+------+--------------+-----+
       |              |
       | (Save State) | (AI Analysis / Prompts)
       v              v
+------+------+  +----+------+
| PostgreSQL  |  |  OpenAI   |
| (Neon DB)   |  |  Copilot  |
+------+------+  +-----------+
       ^
       | (Read Isolated Device State)
+------+------+
|   Next.js   |
|   Frontend  |
|  (Vercel)   |
+-------------+
```

---

## 2. Solo-Developer Deployment Stack

| Component | Target Platform | Purpose | Connection Details |
| :--- | :--- | :--- | :--- |
| **Frontend** | **Vercel** | Host the SOC console and individual host investigation dashboards. | Connects to public FastAPI URL via `NEXT_PUBLIC_API_URL`. |
| **Backend API** | **Render** (or Railway) | Process client telemetry, run threat rules, generate risk scores, and run AI investigations. | Connects to Neon database via `DATABASE_URL`. |
| **Database** | **Neon** (or Supabase) | Store enrolled devices, telemetry snapshots, and heuristic alerts. | Publicly accessible PostgreSQL endpoint with connection pooling. |
| **Endpoint Agent** | **Local Machine** | Collect processes, CPU/RAM stats, and active sockets from your PC. | Sends data directly to the public Render/Railway API. |

---

## 3. Step-by-Step Deployment Steps

### Step 1: Deploy PostgreSQL (Neon)
1. Register for a free account at [Neon](https://neon.tech/).
2. Create a database project named `peszara-xdr`.
3. Go to the dashboard and copy the **Connection String** (choose `PostgreSQL` connection type). It will look similar to this:
   `postgresql://peszara_admin:securepassword@ep-cool-snowflake-12345.us-east-2.aws.neon.tech/neondb?sslmode=require`

### Step 2: Deploy Backend API (Render)
1. Connect your GitHub repository to [Render](https://render.com/).
2. Click **New +** > **Web Service**.
3. Choose your repository and select the following settings:
   * **Root Directory**: `backend`
   * **Runtime**: `Docker` (Render will build directly from `/backend/Dockerfile`)
4. Under **Environment Variables**, configure:
   * `DATABASE_URL` = (Your Neon connection string from Step 1)
   * `OPENAI_API_KEY` = (Your OpenAI API key for threat copilot playbooks)
   * `VIRUSTOTAL_API_KEY` = (Optional: VirusTotal API key)
   * `ABUSEIPDB_API_KEY` = (Optional: AbuseIPDB API key)
5. Deploy. Render will output a public URL like `https://peszara-api.onrender.com`.

### Step 3: Deploy Frontend (Vercel)
1. Go to [Vercel](https://vercel.com/) and connect your repository.
2. Click **Add New** > **Project** and select your project.
3. In the setup wizard:
   * **Root Directory**: `frontend`
   * **Framework Preset**: `Next.js`
4. Expand **Environment Variables** and add:
   * `NEXT_PUBLIC_API_URL` = `https://peszara-api.onrender.com` (Your Render API URL)
5. Click **Deploy**. Vercel will build the frontend and host it at a domain like `https://peszara-xdr.vercel.app`.

### Step 4: Run the Telemetry Agent Locally
1. Clone the project onto the machine you want to monitor.
2. In the terminal, define the environment variable pointing to your deployed Render URL:
   * **Windows (PowerShell)**:
     ```powershell
     $env:PESZARA_BACKEND_URL="https://peszara-api.onrender.com"
     ```
   * **Mac / Linux**:
     ```bash
     export PESZARA_BACKEND_URL="https://peszara-api.onrender.com"
     ```
3. Run the agent:
   ```bash
   cd agent
   pip install -r requirements.txt
   python agent.py
   ```
4. The agent will enroll itself, register a unique `device_id`, and output your custom SOC dashboard link.

---

## 4. Live Demo Sharing Mechanics

### Device-Specific Isolation URL
When presenting this in a portfolio, recruiters do not need to authenticate. Instead, you can share a view-only link scoped to your specific device:
`https://peszara-xdr.vercel.app/device/{device_id}`

### Portfolio Checklist for Interviews
1. **Interactive Demo**: Place a link on your resume: *"Open [https://peszara-xdr.vercel.app/](https://peszara-xdr.vercel.app/) to view real-time endpoints."*
2. **Mock Telemetry**: If your local agent is off, you can run the mock simulation trigger directly on the dashboard screen by clicking **SIMULATE ATTACK**, showing how alerts populate instantaneously.
3. **Data Integrity**: Point out that the backend enforces strict scoping on database queries (filtering by `device_id` on all endpoints), ensuring no cross-device data leaks.
