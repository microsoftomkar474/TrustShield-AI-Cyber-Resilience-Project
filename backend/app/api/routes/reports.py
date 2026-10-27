"""
TrustShield AI — Cyber Resilience Backend
API route: POST /api/v1/cyber/generate-report

Generates a structured investigation report from a scan result.
"""

import logging
from fastapi import APIRouter
from ...schemas.cyber_schemas import ReportRequest, ReportResponse
from ...services.report_generator import ReportGenerator

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/generate-report",
    response_model=ReportResponse,
    summary="Generate an investigation report",
    description="Accepts a scan result and returns a structured, timestamped report.",
    tags=["Cyber Resilience"],
)
async def generate_report(request: ReportRequest) -> ReportResponse:
    report = ReportGenerator.generate(
        scan_type=request.scan_type,
        scan_data=request.scan_data,
        user_notes=request.user_notes,
    )
    return ReportResponse(
        status="success",
        report_id=report["report_id"],
        generated_at=report["generated_at"],
        scan_type=report["scan_type"],
        report_data=report,
    )