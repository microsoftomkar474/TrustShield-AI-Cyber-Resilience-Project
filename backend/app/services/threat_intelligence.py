"""
TrustShield AI — Cyber Resilience Backend
Threat Intelligence Service

Integrates with:
  1. URLhaus (abuse.ch) — no API key required for lookups
  2. PhishTank (optional, requires free API key)

Security requirements:
  - NEVER automatically browse or download content from submitted URLs
  - Lookups are POST requests to TI APIs, not visits to the URL itself
  - Reasonable timeouts prevent hanging
  - External responses are validated before use
  - Graceful degradation when services are unavailable
  - Mock mode clearly labelled — never presented as real intelligence
"""

import httpx
import logging
from datetime import datetime, timezone
from typing import List

from ..schemas.cyber_schemas import ThreatIntelResult
from ..core.config import settings

logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    """
    Optional threat-intelligence integration.

    Falls back gracefully if:
      - THREAT_INTEL_ENABLED is False
      - API is unreachable or times out
      - API key is not configured (PhishTank)
    """

    def __init__(self):
        self.enabled = settings.threat_intel_enabled
        self.timeout = settings.threat_intel_timeout_seconds
        self.urlhaus_url = settings.urlhaus_api_url
        self.urlhaus_auth_key = settings.urlhaus_auth_key
        self.phishtank_api_key = settings.phishtank_api_key
        self.phishtank_url = settings.phishtank_api_url

    async def check_url(self, url: str) -> List[ThreatIntelResult]:
        """
        Query all configured threat-intelligence feeds for a URL.

        Returns a list of ThreatIntelResult objects.
        Never raises — errors are captured in the result objects.

        SECURITY: This sends the URL string to external APIs.
                  It does NOT browse to the URL or download content from it.
        """
        if not self.enabled:
            logger.info("Threat intelligence disabled — skipping lookup")
            return []

        results: List[ThreatIntelResult] = []

        # URLhaus — free, no key required
        urlhaus_result = await self._check_urlhaus(url)
        results.append(urlhaus_result)

        # PhishTank — requires API key
        if self.phishtank_api_key:
            phishtank_result = await self._check_phishtank(url)
            results.append(phishtank_result)
        else:
            logger.debug("PhishTank API key not configured — skipping PhishTank")

        return results

    async def _check_urlhaus(self, url: str) -> ThreatIntelResult:
        """
        Query the URLhaus API.
        API docs: https://urlhaus-api.abuse.ch/

        URLhaus returns:
          query_status: "is_host" / "no_results"
          url_info: dict with url_status, threat, etc.
        """
        queried_at = datetime.now(timezone.utc).isoformat()
        if not self.urlhaus_auth_key:
            return ThreatIntelResult(
                source="URLhaus (abuse.ch)",
                found=False,
                status="Lookup unavailable: Auth-Key not configured",
                queried_at=queried_at,
                error="URLhaus Auth-Key is missing. Local analysis still applies.",
                is_mock=False,
            )
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.urlhaus_url + "url/",
                    data={"url": url},   # Form data, not JSON
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Auth-Key": self.urlhaus_auth_key,
                    },
                )
                response.raise_for_status()
                data = response.json()

                query_status = data.get("query_status", "")
                url_status = data.get("url_status", "")
                threat = data.get("threat", "")

                found = query_status == "is_host" and url_status in ("online", "offline")
                status_str = f"{url_status} | threat: {threat}" if found else "not found in URLhaus"

                return ThreatIntelResult(
                    source="URLhaus (abuse.ch)",
                    found=found,
                    status=status_str,
                    queried_at=queried_at,
                    is_mock=False,
                )

        except httpx.TimeoutException:
            logger.warning("URLhaus lookup timed out for URL (not shown for security)")
            return ThreatIntelResult(
                source="URLhaus (abuse.ch)",
                found=False,
                queried_at=queried_at,
                error="Request timed out. URLhaus was not consulted.",
                is_mock=False,
            )
        except httpx.HTTPStatusError as e:
            logger.warning("URLhaus HTTP error: %s", e.response.status_code)
            return ThreatIntelResult(
                source="URLhaus (abuse.ch)",
                found=False,
                queried_at=queried_at,
                error=f"URLhaus returned HTTP {e.response.status_code}.",
                is_mock=False,
            )
        except Exception as e:
            logger.exception("Unexpected URLhaus error")
            return ThreatIntelResult(
                source="URLhaus (abuse.ch)",
                found=False,
                queried_at=queried_at,
                error="URLhaus lookup failed unexpectedly. Local analysis still applies.",
                is_mock=False,
            )

    async def _check_phishtank(self, url: str) -> ThreatIntelResult:
        """
        Query the PhishTank API.
        API docs: https://www.phishtank.com/api_info.php

        PhishTank returns:
          results.in_database: bool
          results.valid: bool
          results.verified: bool
        """
        queried_at = datetime.now(timezone.utc).isoformat()
        try:
            import urllib.parse as up
            encoded_url = up.quote(url, safe="")

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.phishtank_url,
                    data={
                        "url": encoded_url,
                        "format": "json",
                        "app_key": self.phishtank_api_key,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                response.raise_for_status()
                data = response.json()

                results = data.get("results", {})
                in_db = results.get("in_database", False)
                valid = results.get("valid", False)
                verified = results.get("verified", False)

                found = in_db and valid
                status_str = (
                    f"in_database={in_db}, valid={valid}, verified={verified}"
                    if in_db
                    else "not found in PhishTank"
                )

                return ThreatIntelResult(
                    source="PhishTank",
                    found=found,
                    status=status_str,
                    queried_at=queried_at,
                    is_mock=False,
                )

        except httpx.TimeoutException:
            logger.warning("PhishTank lookup timed out")
            return ThreatIntelResult(
                source="PhishTank",
                found=False,
                queried_at=queried_at,
                error="Request timed out. PhishTank was not consulted.",
                is_mock=False,
            )
        except httpx.HTTPStatusError as e:
            logger.warning("PhishTank HTTP error: %s", e.response.status_code)
            return ThreatIntelResult(
                source="PhishTank",
                found=False,
                queried_at=queried_at,
                error=f"PhishTank returned HTTP {e.response.status_code}.",
                is_mock=False,
            )
        except Exception as e:
            logger.exception("Unexpected PhishTank error")
            return ThreatIntelResult(
                source="PhishTank",
                found=False,
                queried_at=queried_at,
                error="PhishTank lookup failed unexpectedly. Local analysis still applies.",
                is_mock=False,
            )

    @staticmethod
    def is_confirmed_malicious(results: List[ThreatIntelResult]) -> bool:
        """
        Returns True if any non-mock TI result found the URL as malicious.
        Used by the risk assessor to override rule-based score.
        """
        return any(r.found and not r.is_mock for r in results)

    @staticmethod
    def correlate_verdict(results: List[ThreatIntelResult]) -> dict:
        """
        Correlate results from multiple threat feeds into a single verdict.
        
        Returns a dict with:
          - verdict: "MALICIOUS" | "CLEAN" | "MIXED" | "INCONCLUSIVE"
          - confidence: "HIGH" | "MEDIUM" | "LOW"
          - reasoning: Human-readable explanation
        """
        if not results:
            return {
                "verdict": "INCONCLUSIVE",
                "confidence": "LOW",
                "reasoning": "No threat intelligence feeds were queried.",
            }

        found_count = sum(1 for r in results if r.found and not r.is_mock)
        error_count = sum(1 for r in results if r.error)
        clean_count = sum(1 for r in results if not r.found and not r.error and not r.is_mock)
        total_queried = len([r for r in results if not r.is_mock])

        if found_count > 0:
            if error_count > 0:
                return {
                    "verdict": "MALICIOUS",
                    "confidence": "HIGH",
                    "reasoning": f"Found in {found_count} feed(s). {error_count} feed(s) unavailable, but confirmed malicious evidence takes precedence.",
                }
            return {
                "verdict": "MALICIOUS",
                "confidence": "HIGH",
                "reasoning": f"Confirmed malicious in {found_count} of {total_queried} queried feeds.",
            }

        if error_count == total_queried:
            return {
                "verdict": "INCONCLUSIVE",
                "confidence": "LOW",
                "reasoning": "All queried threat intelligence feeds were unavailable. Local analysis still applies.",
            }

        if error_count > 0 and clean_count > 0:
            return {
                "verdict": "MIXED",
                "confidence": "MEDIUM",
                "reasoning": f"{clean_count} feed(s) returned clean results, but {error_count} feed(s) were unavailable. Incomplete evidence.",
            }

        return {
            "verdict": "CLEAN",
            "confidence": "MEDIUM",
            "reasoning": f"Not found in any of the {total_queried} queried feeds. This is not proof of safety.",
        }