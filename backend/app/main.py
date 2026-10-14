"""
SentinelAI - Real-Time Autonomous Defense Backend
==================================================
FastAPI application serving line-rate multi-tier AI inference,
threat attribution, and live WebSocket security telemetry.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.api.endpoints import router as api_router
from backend.app.services.inference_engine import SentinelInferenceEngine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler: preload AI models into memory on server startup."""
    print("=" * 70, flush=True)
    print("  🚀 INITIALIZING SENTINELAI DEFENSE ENGINE...", flush=True)
    print("=" * 70, flush=True)
    engine = SentinelInferenceEngine.get_instance()
    print(f"[+] Multi-Tier Engine Online: {len(engine.classes)} MITRE attack categories armed.", flush=True)
    yield
    print("[*] SentinelAI Defense Engine Shutting Down...", flush=True)


app = FastAPI(
    title="SentinelAI Autonomous Defense Engine",
    description="High-Throughput Multi-Tier AI Network Intrusion Detection & Threat Attribution API",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for SOC dashboard frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes
app.include_router(api_router, prefix="/api")


@app.get("/", tags=["Root"])
def root():
    return {
        "platform": "SentinelAI Autonomous Cyber Defense",
        "version": "1.0.0",
        "status": "OPERATIONAL",
        "docs_url": "/docs",
        "redoc_url": "/redoc"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
