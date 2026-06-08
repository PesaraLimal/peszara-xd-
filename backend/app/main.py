from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, Base
from .routers import devices, telemetry, alerts, reports
from .config import HOST, PORT

# Create database tables automatically
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="PESZARA XDR Backend",
    description="Threat Detection, Endpoint Telemetry Ingestion, and Incident Investigation API",
    version="1.0.0"
)

# Set up CORS middleware for Next.js app communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, lock this down to the Next.js origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(devices.router)
app.include_router(telemetry.router)
app.include_router(alerts.router)
app.include_router(reports.router)

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "PESZARA XDR Engine",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=HOST, port=PORT, reload=True)
