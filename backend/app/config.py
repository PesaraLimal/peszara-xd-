import os
import socket
from dotenv import load_dotenv

load_dotenv()

class Settings:
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./peszara.db")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://host.docker.internal:11434")
    REGISTRATION_KEY: str = os.getenv("REGISTRATION_KEY", "PESZARA_SECURE_REG_2026")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "peszara_admin_pass")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "peszara_jwt_secret_key_long_and_secure")

    
    # Self-healing: if the URL points to the Docker host "db" but it is unresolvable on the host system, force SQLite.
    if "@db:" in DATABASE_URL or "://db:" in DATABASE_URL:
        try:
            socket.gethostbyname("db")
        except socket.gaierror:
            DATABASE_URL = "sqlite:///./peszara.db"
    
settings = Settings()
