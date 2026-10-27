"""
TrustShield AI — Cyber Resilience Backend
API Router

Registers all route modules with the '/cyber' prefix.
"""

from fastapi import APIRouter
from .routes import url_scans, message_scans, incident_guidance, reports

# main.py imports this as 'api_router' and adds '/api/v1'
api_router = APIRouter()

api_router.include_router(
    url_scans.router,
    prefix="/cyber",
    tags=["Cyber Resilience"]
)
api_router.include_router(
    message_scans.router,
    prefix="/cyber",
    tags=["Cyber Resilience"]
)
api_router.include_router(
    incident_guidance.router,
    prefix="/cyber",
    tags=["Cyber Resilience"]
)
api_router.include_router(
    reports.router,
    prefix="/cyber",
    tags=["Cyber Resilience"]
)