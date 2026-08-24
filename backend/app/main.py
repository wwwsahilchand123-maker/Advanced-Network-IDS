"""
Main FastAPI application with WebSocket support
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime

from app.core.config import settings
from app.core.logging import setup_logging, get_logger
from app.api import auth, capture, alerts, incidents, dashboard
from app.api import websocket as ws
from app.websocket.events import broadcaster

# Setup logging
setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"Debug mode: {settings.DEBUG}")
    
    # Start WebSocket broadcaster
    await broadcaster.start()
    logger.info("WebSocket broadcaster started")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")
    await broadcaster.stop()
    logger.info("WebSocket broadcaster stopped")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Advanced Network Intrusion Detection System - Production-Grade SOC Platform",
    lifespan=lifespan,
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json"
)

# CORS middleware - Allow WebSocket connections
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include HTTP routers
app.include_router(
    auth.router,
    prefix=f"{settings.API_V1_PREFIX}/auth",
    tags=["Authentication"]
)

app.include_router(
    capture.router,
    prefix=f"{settings.API_V1_PREFIX}/capture",
    tags=["Capture"]
)

app.include_router(
    alerts.router,
    prefix=f"{settings.API_V1_PREFIX}/alerts",
    tags=["Alerts"]
)

app.include_router(
    incidents.router,
    prefix=f"{settings.API_V1_PREFIX}/incidents",
    tags=["Incidents"]
)

app.include_router(
    dashboard.router,
    prefix=f"{settings.API_V1_PREFIX}/dashboard",
    tags=["Dashboard"]
)

# Include WebSocket router
app.include_router(
    ws.router,
    prefix=f"{settings.API_V1_PREFIX}/ws",
    tags=["WebSocket"]
)


@app.get("/")
def root():
    """Root endpoint"""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "description": "Advanced Network Intrusion Detection System",
        "websocket_url": f"ws://localhost:8000{settings.API_V1_PREFIX}/ws/events"
    }


@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "websocket_enabled": True
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )
