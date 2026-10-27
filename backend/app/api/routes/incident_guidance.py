"""
TrustShield AI — Cyber Resilience Backend
API route: POST /api/v1/cyber/incident-guidance

Generates a personalized incident response plan based on detected indicators.
"""

from fastapi import APIRouter
from ...schemas.cyber_schemas import IncidentGuidanceRequest, IncidentGuidanceResponse
from ...services.incident_assistant import IncidentAssistant

router = APIRouter()

@router.post(
    "/incident-guidance",
    response_model=IncidentGuidanceResponse,
    summary="Generate personalized incident response guidance",
    description=(
        "Accepts a list of indicator codes from a prior scan and returns "
        "step-by-step containment and recovery actions tailored to the threat."
    ),
    tags=["Cyber Resilience"],
)
async def generate_incident_guidance(request: IncidentGuidanceRequest) -> IncidentGuidanceResponse:
    guidance = IncidentAssistant.generate_guidance(
        indicators=request.indicator_codes,
        context=request.context
    )
    return IncidentGuidanceResponse(**guidance)