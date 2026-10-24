"""
TrustShield AI — Cyber Resilience Backend
API route: POST /api/v1/cyber/message-scans

Handles suspicious message analysis requests.
Orchestrates: MessageAnalyzer → URLAnalyzer → RiskAssessor → Response
"""

import logging
from fastapi import APIRouter

from ...schemas.cyber_schemas import (
    MessageScanRequest, MessageScanResponse, ExtractedURL,
    RiskLevel, ScoreType,
)
from ...services.message_analyzer import MessageAnalyzer
from ...services.url_analyzer import URLAnalyzer
from ...services.risk_assessment import RiskAssessor, LIMITATIONS_TEXT
from ...services.threat_intelligence import ThreatIntelligenceService
from .url_scans import _url_analyzer, _risk_assessor, _threat_intel

logger = logging.getLogger(__name__)
router = APIRouter()

_message_analyzer = MessageAnalyzer()


@router.post(
    "/message-scans",
    response_model=MessageScanResponse,
    summary="Analyse a suspicious message for phishing indicators",
    description=(
        "Submits a text message for phishing analysis. "
        "Detects credential requests, urgency tactics, impersonation, and "
        "suspicious links. URLs found in the message are individually analysed."
    ),
    tags=["Cyber Resilience"],
)
async def create_message_scan(request: MessageScanRequest) -> MessageScanResponse:
    """
    POST /api/v1/cyber/message-scans

    Workflow:
      1. MessageAnalyzer detects phishing patterns in text
      2. URLs are extracted from the message
      3. Each URL is individually analysed via URLAnalyzer + TI
      4. RiskAssessor combines message + URL signals
      5. Recommendations are generated
      6. Response is assembled and returned
    """
    message = request.message
    logger.info("Message scan requested")

    try:
        # Step 1 — Text-level phishing analysis
        msg_indicators, extracted_url_strings = _message_analyzer.analyse(message)

        # Step 2+3 — Analyse each extracted URL individually
        extracted_urls: list[ExtractedURL] = []
        url_labels: list[RiskLevel] = []

        for url_str in extracted_url_strings[:10]:  # Limit to 10 URLs per message
            try:
                url_indicators, parsed_components = _url_analyzer.analyse(url_str)
                ti_results = await _threat_intel.check_url(url_str)
                ti_confirmed = ThreatIntelligenceService.is_confirmed_malicious(ti_results)
                url_label, url_score = _risk_assessor.assess_url(url_indicators, ti_confirmed)
                url_labels.append(url_label)
                url_score_type = (
                    ScoreType.THREAT_INTEL_CONFIRMED if ti_confirmed
                    else ScoreType.RULE_BASED
                )

                from ...schemas.cyber_schemas import URLScanResponse
                url_scan_result = URLScanResponse(
                    status="success",
                    module="cyber_resilience",
                    label=url_label,
                    score=url_score,
                    score_type=url_score_type,
                    evidence=url_indicators,
                    model_or_feed_version="rule_engine_v1",
                    limitations=LIMITATIONS_TEXT,
                    url_analysed=url_str,
                    parsed_components=parsed_components,
                    threat_intelligence=ti_results,
                    recommendations=RiskAssessor.get_url_recommendations(
                        url_label, url_indicators
                    ),
                )
                extracted_urls.append(ExtractedURL(
                    url=url_str, scan_result=url_scan_result
                ))
            except Exception as e:
                logger.warning("URL sub-analysis failed: %s", type(e).__name__)
                extracted_urls.append(ExtractedURL(url=url_str, scan_result=None))

        # Step 4 — Combined risk assessment
        label, score = _risk_assessor.assess_message(msg_indicators, url_labels)

        # Step 5 — Recommendations
        recommendations = RiskAssessor.get_message_recommendations(label, msg_indicators)

        # Step 6 — Response
        return MessageScanResponse(
            status="success",
            module="cyber_resilience",
            label=label,
            score=score,
            score_type=ScoreType.RULE_BASED,
            evidence=msg_indicators,
            model_or_feed_version="rule_engine_v1",
            limitations=LIMITATIONS_TEXT,
            message_preview=message[:200],
            extracted_urls=extracted_urls,
            recommendations=recommendations,
        )

    except Exception as e:
        logger.exception("Unexpected error during message scan")
        return MessageScanResponse(
            status="error",
            module="cyber_resilience",
            label=RiskLevel.HIGH,
            score=1.0,
            score_type=ScoreType.RULE_BASED,
            evidence=[],
            model_or_feed_version="rule_engine_v1",
            limitations=LIMITATIONS_TEXT,
            message_preview=message[:200],
            extracted_urls=[],
            recommendations=["Analysis failed. Treat this message with extreme caution."],
            error=f"Internal analysis error: {type(e).__name__}",
        )
