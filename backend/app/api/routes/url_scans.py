"""
TrustShield AI — Cyber Resilience Backend
API route: POST /api/v1/cyber/url-scans

Handles URL phishing analysis requests.
Orchestrates: URLAnalyzer → ThreatIntelligence → RiskAssessor → Response
"""

import logging
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse

from ...schemas.cyber_schemas import (
    URLScanRequest, URLScanResponse, RiskLevel, ScoreType,
)
from ...services.url_analyzer import URLAnalyzer
from ...services.risk_assessment import RiskAssessor, LIMITATIONS_TEXT
from ...services.threat_intelligence import ThreatIntelligenceService

logger = logging.getLogger(__name__)
router = APIRouter()

# Service singletons — stateless, safe to share
_url_analyzer = URLAnalyzer()
_risk_assessor = RiskAssessor()
_threat_intel = ThreatIntelligenceService()


@router.post(
    "/url-scans",
    response_model=URLScanResponse,
    summary="Analyse a URL for phishing indicators",
    description=(
        "Submits a URL for rule-based phishing analysis and optional "
        "threat-intelligence lookup. Returns a risk classification "
        "(LOW / MEDIUM / HIGH), detected indicators, and recommendations."
    ),
    tags=["Cyber Resilience"],
)
async def create_url_scan(request: URLScanRequest) -> URLScanResponse:
    """
    POST /api/v1/cyber/url-scans

    Workflow:
      1. URLAnalyzer runs rule-based checks on the URL string
      2. ThreatIntelligenceService queries URLhaus (+ PhishTank if configured)
      3. RiskAssessor computes score and label
      4. Recommendations are generated
      5. Response is assembled and returned
    """
    url = request.url
    logger.info("URL scan requested (URL not logged for security)")

    try:
        # Step 1 — Rule-based URL analysis (no network call to the URL itself)
        indicators, parsed_components = _url_analyzer.analyse(url)

        # Step 2 — Threat intelligence lookups (optional, graceful failure)
        ti_results = await _threat_intel.check_url(url)
        ti_confirmed = ThreatIntelligenceService.is_confirmed_malicious(ti_results)

        # Step 3 — Risk assessment
        label, score = _risk_assessor.assess_url(indicators, ti_confirmed)

        # Step 4 — Recommendations
        recommendations = RiskAssessor.get_url_recommendations(label, indicators)

        # Step 5 — Score type
        score_type = (
            ScoreType.THREAT_INTEL_CONFIRMED if ti_confirmed
            else ScoreType.RULE_BASED
        )

        return URLScanResponse(
            status="success",
            module="cyber_resilience",
            label=label,
            score=score,
            score_type=score_type,
            evidence=indicators,
            model_or_feed_version="rule_engine_v1",
            limitations=LIMITATIONS_TEXT,
            url_analysed=url,
            parsed_components=parsed_components,
            threat_intelligence=ti_results,
            recommendations=recommendations,
        )

    except Exception as e:
        logger.exception("Unexpected error during URL scan")
        return URLScanResponse(
            status="error",
            module="cyber_resilience",
            label=RiskLevel.HIGH,   # Fail-safe: unknown error → treat as high risk
            score=1.0,
            score_type=ScoreType.RULE_BASED,
            evidence=[],
            model_or_feed_version="rule_engine_v1",
            limitations=LIMITATIONS_TEXT,
            url_analysed=url,
            parsed_components={},
            threat_intelligence=[],
            recommendations=["Analysis failed. Treat this URL with extreme caution."],
            error=f"Internal analysis error: {type(e).__name__}",
        )
