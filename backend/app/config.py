import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./peszara_xdr.db")

# Threat Intelligence & AI Copilot Keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# Server configuration
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))
