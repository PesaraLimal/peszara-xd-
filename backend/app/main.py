import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base
from app.routers import devices, telemetry, alerts, ai_copilot

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("PeszaraBackend")

# Initialize Database tables
logger.info("Initializing database tables...")
try:
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables initialized successfully.")
except Exception as e:
    logger.error(f"Critical error creating database tables: {e}", exc_info=True)

# Initialize FastAPI App
app = FastAPI(
    title="PESZARA XDR Backend",
    description="Threat Detection, Ingestion, & Investigation Engine API",
    version="1.0.0"
)

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For dev simplicity, allow all. In production, restrict to localhost:3000
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(telemetry.router)
app.include_router(devices.router)
app.include_router(alerts.router)
app.include_router(ai_copilot.router)

@app.get("/api/v1/health")
def health_check():
    """Service status health check."""
    return {"status": "healthy", "service": "PESZARA XDR Backend"}
