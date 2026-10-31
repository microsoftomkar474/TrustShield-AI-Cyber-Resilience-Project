"""
TrustShield AI — Cyber Resilience Backend
FastAPI application entry point

Creates the FastAPI app with:
  - CORS middleware configured for the React frontend
  - Health check endpoint
  - Cyber Resilience API routes
  - Structured error handling
"""

import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from .core.config import settings
from .api.router import api_router

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.app_log_level.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

# ============================================================
# Create FastAPI application
# ============================================================
app = FastAPI(
    title="TrustShield AI — Cyber Resilience API",
    description=(
        "Member 4: Cyber Resilience module for the TrustShield AI hackathon project.\n\n"
        "Provides URL phishing analysis, suspicious message analysis, "
        "and threat-intelligence integration.\n\n"
        "**POST** `/api/v1/cyber/url-scans` — Analyse a URL\n\n"
        "**POST** `/api/v1/cyber/message-scans` — Analyse a suspicious message"
    ),
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ============================================================
# CORS Middleware
# Allows the React frontend (on a different port) to call this API.
# In production, restrict origins to the exact frontend URL.
# F10: Warn loudly if wildcard origins are configured with credentials.
# ============================================================
_cors_origins = settings.cors_origins_list
if "*" in _cors_origins:
    logger.critical(
        "SECURITY WARNING: CORS_ORIGINS contains '*' (wildcard). "
        "This is unsafe when allow_credentials=True. "
        "Set CORS_ORIGINS to specific frontend origins in production."
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# ============================================================
# Global exception handler
# Catches any unhandled exceptions and returns structured JSON
# ============================================================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # F9: Log the real exception server-side only.
    # Never return exception class names or internal details to the client.
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "module": "cyber_resilience",
            "error": "An unexpected server error occurred.",
            "detail": "internal_error",
        },
    )

# ============================================================
# Include API routes
# ============================================================
app.include_router(api_router, prefix="/api/v1")

# ============================================================
# Health check endpoint
# ============================================================
@app.get(
    "/health",
    summary="Health check",
    description="Returns server status. Used by monitoring and integration tests.",
    tags=["Health"],
)
async def health_check():
    return {
        "status": "healthy",
        "module": "cyber_resilience",
        "version": "1.0.0",
        "environment": settings.app_env,
    }

@app.get(
    "/",
    summary="Root",
    description="Redirects to API documentation.",
    tags=["Health"],
)
async def root():
    return {
        "message": "TrustShield AI — Cyber Resilience API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "url_scan": "POST /api/v1/cyber/url-scans",
            "message_scan": "POST /api/v1/cyber/message-scans",
        },
    }
