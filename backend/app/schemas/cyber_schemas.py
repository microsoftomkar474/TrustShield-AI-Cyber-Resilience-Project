"""
TrustShield AI — Cyber Resilience Backend
Pydantic schemas for API request/response models.

These schemas define the public API contract.
Member 1's main application consumes these exact shapes.

Upgrade history:
- v1.1: F5 — Added UNKNOWN to RiskLevel (insufficient evidence state)
- v1.1: F7 — Added LookupStatus enum and lookup_status field to ThreatIntelResult
"""

from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Dict, Any
from enum import Enum
import re


# ============================================================
# Shared Enums
# ============================================================

class RiskLevel(str, Enum):
    """
    Risk classification used across all analysis types.

    UNKNOWN: Returned when evidence is insufficient for a reliable verdict
             (e.g. all threat-intelligence feeds were unavailable and
             heuristic indicators are borderline). Callers must NOT treat
             UNKNOWN as LOW — it means 'we do not know'.
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    UNKNOWN = "UNKNOWN"


class ScoreType(str, Enum):
    """Describes how the score was computed."""
    RULE_BASED = "rule_based"          # Deterministic rules, no ML
    THREAT_INTEL_CONFIRMED = "threat_intel_confirmed"  # External feed match
    MOCK = "mock"                       # Test/fallback — never shown as real


# ============================================================
# URL Scan — Request
# ============================================================

class URLScanRequest(BaseModel):
    """Request body for POST /api/v1/cyber/url-scans"""

    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="The URL to analyse. Must be a string.",
        examples=["https://example.com/login?ref=email"],
    )

    @field_validator("url")
    @classmethod
    def strip_url(cls, v: str) -> str:
        """Strip surrounding whitespace from submitted URLs."""
        return v.strip()


# ============================================================
# URL Scan — Response
# ============================================================

class URLIndicator(BaseModel):
    """A single detected phishing indicator in a URL."""

    code: str = Field(
        description="Machine-readable reason code, e.g. URL_IP_ADDRESS_HOST"
    )
    description: str = Field(
        description="Human-readable explanation of why this is suspicious"
    )
    risk_contribution: str = Field(
        description="How much this indicator contributes: LOW / MEDIUM / HIGH"
    )


class LookupStatus(str, Enum):
    """
    Structured status of a threat-intelligence lookup. (F7)

    This replaces ambiguous boolean found=False which conflated
    'checked and not found' with 'service unavailable'.

    NOT_CONFIGURED: API key or service is not set up.
    CLEAN:          Lookup succeeded and URL was not found.
    MALICIOUS:      Lookup succeeded and URL was confirmed malicious.
    ERROR:          HTTP error or unexpected response from the feed.
    TIMEOUT:        Network timeout — feed was not consulted.
    DISABLED:       Threat intelligence is disabled in configuration.
    """
    NOT_CONFIGURED = "NOT_CONFIGURED"
    CLEAN = "CLEAN"
    MALICIOUS = "MALICIOUS"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    DISABLED = "DISABLED"


class ThreatIntelResult(BaseModel):
    """Result from an external threat-intelligence feed."""

    source: str = Field(description="Name of the intelligence feed")
    found: bool = Field(description="Whether the URL was found in the feed")
    lookup_status: LookupStatus = Field(
        default=LookupStatus.CLEAN,
        description=(
            "Structured lookup outcome. Use this — not found=False — "
            "to distinguish 'checked clean' from 'service unavailable'."
        ),
    )
    status: Optional[str] = Field(
        default=None,
        description="Feed-specific status string (e.g. 'online', 'phishing')"
    )
    queried_at: Optional[str] = Field(
        default=None, description="ISO-8601 timestamp of the lookup"
    )
    error: Optional[str] = Field(
        default=None, description="Error message if the lookup failed"
    )
    is_mock: bool = Field(
        default=False,
        description="True when this result is simulated (no real API call made)"
    )


class URLScanResponse(BaseModel):
    """
    Response body for POST /api/v1/cyber/url-scans.

    This is the agreed API contract with Member 1's main application.
    Field names must not change without team agreement.
    """

    # --- Team-agreed integration fields ---
    status: str = Field(
        description="'success' or 'error'",
        examples=["success"],
    )
    module: str = Field(
        default="cyber_resilience",
        description="Identifies this module to the main application",
    )
    label: RiskLevel = Field(
        description="Final risk classification: LOW, MEDIUM, or HIGH"
    )
    score: float = Field(
        description="Numeric risk score (0.0 – 1.0 range, rule-based)"
    )
    score_type: ScoreType = Field(
        description="How the score was computed"
    )
    evidence: List[URLIndicator] = Field(
        default_factory=list,
        description="List of detected phishing indicators",
    )
    model_or_feed_version: str = Field(
        default="rule_engine_v1",
        description="Version identifier for reproducibility",
    )
    limitations: str = Field(
        description="Known limitations of this analysis"
    )

    # --- Module-specific detail fields ---
    url_analysed: str = Field(description="The URL that was analysed")
    parsed_components: Dict[str, Any] = Field(
        default_factory=dict,
        description="Parsed URL components (scheme, host, path, etc.)",
    )
    threat_intelligence: List[ThreatIntelResult] = Field(
        default_factory=list,
        description="Results from external threat-intelligence feeds",
    )
    recommendations: List[str] = Field(
        default_factory=list,
        description="Actionable recommendations for the user",
    )

    # --- Error field (populated only on failure) ---
    error: Optional[str] = Field(
        default=None, description="Error description if status is 'error'"
    )


# ============================================================
# Message Scan — Request
# ============================================================

class MessageScanRequest(BaseModel):
    """Request body for POST /api/v1/cyber/message-scans"""

    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="The suspicious message text to analyse",
        examples=["Your account has been suspended. Click here to verify: http://verify-account.xyz/login"],
    )

    @field_validator("message")
    @classmethod
    def strip_and_validate_message(cls, v: str) -> str:
        """Strip surrounding whitespace and reject whitespace-only messages."""
        stripped = v.strip()
        if not stripped:
            raise ValueError("Message must not be empty or consist only of whitespace.")
        return stripped


# ============================================================
# Message Scan — Response
# ============================================================

class MessageIndicator(BaseModel):
    """A single detected phishing indicator in a message."""

    code: str = Field(description="Machine-readable reason code")
    description: str = Field(description="Human-readable explanation")
    matched_text: Optional[str] = Field(
        default=None,
        description="The specific text fragment that triggered this indicator",
    )
    risk_contribution: str = Field(
        description="LOW / MEDIUM / HIGH contribution"
    )


class ExtractedURL(BaseModel):
    """A URL extracted from a message, with its own analysis results."""

    url: str = Field(description="The extracted URL")
    scan_result: Optional[URLScanResponse] = Field(
        default=None, description="Full URL scan result for this URL"
    )


class MessageScanResponse(BaseModel):
    """
    Response body for POST /api/v1/cyber/message-scans.

    This is the agreed API contract with Member 1's main application.
    """

    # --- Team-agreed integration fields ---
    status: str = Field(description="'success' or 'error'")
    module: str = Field(default="cyber_resilience")
    label: RiskLevel = Field(
        description="Overall message risk: LOW, MEDIUM, or HIGH"
    )
    score: float = Field(description="Numeric risk score (0.0 – 1.0)")
    score_type: ScoreType = Field(description="How the score was computed")
    evidence: List[MessageIndicator] = Field(
        default_factory=list,
        description="Detected phishing indicators in the message",
    )
    model_or_feed_version: str = Field(default="rule_engine_v1")
    limitations: str = Field(description="Known limitations of this analysis")

    # --- Module-specific fields ---
    message_preview: str = Field(
        description="First 200 characters of the analysed message"
    )
    extracted_urls: List[ExtractedURL] = Field(
        default_factory=list,
        description="URLs found in the message with individual analysis",
    )
    recommendations: List[str] = Field(
        default_factory=list,
        description="Actionable recommendations for the user",
    )

    # --- Error field ---
    error: Optional[str] = Field(default=None)


# ============================================================
# F4: Incident Assistant Schemas
# ============================================================

class IncidentGuidanceRequest(BaseModel):
    """Request body for POST /api/v1/cyber/incident-guidance"""
    
    indicator_codes: List[str] = Field(
        ..., 
        description="List of indicator codes detected from a previous scan"
    )
    context: str = Field(
        default="URL", 
        description="Whether this is from a URL or MESSAGE scan"
    )


class IncidentAction(BaseModel):
    """A single step in the incident response plan."""
    
    step: int
    title: str
    description: str


class IncidentGuidanceResponse(BaseModel):
    """Response body for POST /api/v1/cyber/incident-guidance"""
    
    status: str = "success"
    severity: str = Field(description="'CRITICAL' or 'HIGH'")
    context: str
    actions: List[IncidentAction]
    disclaimer: str

    
# ============================================================
# F6: Cyber Investigation Report Schemas
# ============================================================

class ReportRequest(BaseModel):
    """Request body for POST /api/v1/cyber/generate-report"""
    scan_type: str = Field(..., description="'url' or 'message'")
    scan_data: Dict[str, Any] = Field(..., description="The full scan response object")
    user_notes: Optional[str] = Field(default=None, description="Optional user notes for the report")


class ReportResponse(BaseModel):
    """Response body for POST /api/v1/cyber/generate-report"""
    status: str = "success"
    report_id: str
    generated_at: str
    scan_type: str
    report_data: Dict[str, Any]