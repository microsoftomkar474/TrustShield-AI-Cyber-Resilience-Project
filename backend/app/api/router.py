"""
TrustShield AI — Cyber Resilience Backend
API router aggregator

Collects all route modules under the /api/v1/cyber prefix.
"""

from fastapi import APIRouter
from .routes import url_scans, message_scans

api_router = APIRouter(prefix="/api/v1/cyber")

api_router.include_router(url_scans.router)
api_router.include_router(message_scans.router)
