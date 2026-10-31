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

Upgrade history:
- v1.1: F7 — All ThreatIntelResult objects now include structured lookup_status
         (LookupStatus enum) so callers can distinguish CLEAN from UNAVAILABLE
- v1.1: F8 — TTL in-memory cache (5 minutes) to avoid redundant API calls
         for the same URL within a short window
- v1.1: Explicit handling of HTTP 429 (rate limit) status
- v1.1: Auth-key validation for URLhaus before making request
"""

import hashlib
import httpx
import logging
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Optional

from ..schemas.cyber_schemas import ThreatIntelResult, LookupStatus
from ..core.config import settings

logger = logging.getLogger(__name__)


# ============================================================
# Bounded Thread-Safe TTL Cache (F8 upgrade)
# ============================================================
_CACHE_TTL_SECONDS = 300  # 5 minutes
_CACHE_MAX_SIZE = 1000   # Bounded maximum capacity


class BoundedTTLCache:
    """
    Thread-safe, bounded in-memory cache with monotonic TTL expiration and LRU eviction.

    Key: (source: str, url_sha256: str)
    Value: (ThreatIntelResult, expiry_timestamp_monotonic: float)
    """

    def __init__(self, maxsize: int = _CACHE_MAX_SIZE, ttl_seconds: float = _CACHE_TTL_SECONDS):
        self.maxsize = maxsize
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[Tuple[str, str], Tuple[ThreatIntelResult, float]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Tuple[str, str]) -> Optional[ThreatIntelResult]:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            result, expiry = entry
            now = time.monotonic()
            if now > expiry:
                self._cache.pop(key, None)
                return None
            self._cache.move_to_end(key)
            return result

    def set(self, key: Tuple[str, str], result: ThreatIntelResult) -> None:
        with self._lock:
            now = time.monotonic()
            if key in self._cache:
                self._cache[key] = (result, now + self.ttl_seconds)
                self._cache.move_to_end(key)
                return

            if len(self._cache) >= self.maxsize:
                # Evict expired entries first
                expired = [k for k, (_, exp) in self._cache.items() if now > exp]
                for k in expired:
                    self._cache.pop(k, None)

                # If still at max capacity, evict the least recently used entry (first in OrderedDict)
                while len(self._cache) >= self.maxsize:
                    self._cache.popitem(last=False)

            self._cache[key] = (result, now + self.ttl_seconds)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)

    def __contains__(self, key: Tuple[str, str]) -> bool:
        with self._lock:
            return key in self._cache


_ti_cache = BoundedTTLCache(maxsize=_CACHE_MAX_SIZE, ttl_seconds=_CACHE_TTL_SECONDS)


def clear_ti_cache() -> None:
    """
    Clear the threat-intelligence in-memory cache.

    Intended for use in tests to prevent cross-test cache pollution.
    Do NOT call this in production code.
    """
    _ti_cache.clear()


def _cache_key(source: str, url: str) -> Tuple[str, str]:
    """
    Return a cache key for a (source, url) pair.
    We hash the URL so it never appears in memory in cleartext
    beyond what httpx already holds during the request.
    """
    url_hash = hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest()
    return (source, url_hash)


def _cache_get(source: str, url: str) -> Optional[ThreatIntelResult]:
    """Return cached result if still within TTL and capacity, else None."""
    return _ti_cache.get(_cache_key(source, url))


def _cache_set(source: str, url: str, result: ThreatIntelResult) -> None:
    """Store result in bounded cache with TTL expiry."""
    _ti_cache.set(_cache_key(source, url), result)


class ThreatIntelligenceService:
    """
    Optional threat-intelligence integration.

    Falls back gracefully if:
      - THREAT_INTEL_ENABLED is False
      - API is unreachable or times out
      - API key is not configured (PhishTank)

    All ThreatIntelResult objects include lookup_status (F7) so that
    callers can distinguish between:
      - LookupStatus.CLEAN       → checked, URL not found
      - LookupStatus.MALICIOUS   → checked, URL is confirmed malicious
      - LookupStatus.NOT_CONFIGURED → API key missing, not queried
      - LookupStatus.TIMEOUT     → request timed out
      - LookupStatus.ERROR       → HTTP or unexpected error
      - LookupStatus.DISABLED    → TI globally disabled
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
            return [ThreatIntelResult(
                source="ThreatIntelligence",
                found=False,
                lookup_status=LookupStatus.DISABLED,
                queried_at=datetime.now(timezone.utc).isoformat(),
                status="Threat intelligence is disabled in configuration.",
                is_mock=False,
            )]

        results: List[ThreatIntelResult] = []

        # URLhaus — free, auth key required for reliable lookups
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
        source = "URLhaus (abuse.ch)"

        # Check cache first (F8)
        cached = _cache_get(source, url)
        if cached is not None:
            logger.debug("URLhaus result served from cache")
            return cached

        if not self.urlhaus_auth_key:
            result = ThreatIntelResult(
                source=source,
                found=False,
                lookup_status=LookupStatus.NOT_CONFIGURED,
                status="Lookup unavailable: Auth-Key not configured",
                queried_at=queried_at,
                error="URLhaus Auth-Key is missing. Local analysis still applies.",
                is_mock=False,
            )
            # Do NOT cache not-configured results (config may change)
            return result

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
                lkup_status = LookupStatus.MALICIOUS if found else LookupStatus.CLEAN

                result = ThreatIntelResult(
                    source=source,
                    found=found,
                    lookup_status=lkup_status,
                    status=status_str,
                    queried_at=queried_at,
                    is_mock=False,
                )
                _cache_set(source, url, result)
                return result

        except httpx.TimeoutException:
            logger.warning("URLhaus lookup timed out for URL (not shown for security)")
            return ThreatIntelResult(
                source=source,
                found=False,
                lookup_status=LookupStatus.TIMEOUT,
                queried_at=queried_at,
                error="Request timed out. URLhaus was not consulted.",
                is_mock=False,
            )
        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code
            logger.warning("URLhaus HTTP error: %s", status_code)
            # Handle specific HTTP errors distinctly
            if status_code == 401:
                error_msg = "URLhaus returned HTTP 401 — invalid or missing Auth-Key."
            elif status_code == 403:
                error_msg = "URLhaus returned HTTP 403 — access forbidden."
            elif status_code == 429:
                error_msg = "URLhaus returned HTTP 429 — rate limit exceeded. Try again later."
            else:
                error_msg = f"URLhaus returned HTTP {status_code}."
            return ThreatIntelResult(
                source=source,
                found=False,
                lookup_status=LookupStatus.ERROR,
                queried_at=queried_at,
                error=error_msg,
                is_mock=False,
            )
        except Exception:
            logger.exception("Unexpected URLhaus error")
            return ThreatIntelResult(
                source=source,
                found=False,
                lookup_status=LookupStatus.ERROR,
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
        source = "PhishTank"

        # Check cache first (F8)
        cached = _cache_get(source, url)
        if cached is not None:
            logger.debug("PhishTank result served from cache")
            return cached

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
                lkup_status = LookupStatus.MALICIOUS if found else LookupStatus.CLEAN

                result = ThreatIntelResult(
                    source=source,
                    found=found,
                    lookup_status=lkup_status,
                    status=status_str,
                    queried_at=queried_at,
                    is_mock=False,
                )
                _cache_set(source, url, result)
                return result

        except httpx.TimeoutException:
            logger.warning("PhishTank lookup timed out")
            return ThreatIntelResult(
                source=source,
                found=False,
                lookup_status=LookupStatus.TIMEOUT,
                queried_at=queried_at,
                error="Request timed out. PhishTank was not consulted.",
                is_mock=False,
            )
        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code
            logger.warning("PhishTank HTTP error: %s", status_code)
            if status_code == 429:
                error_msg = "PhishTank returned HTTP 429 — rate limit exceeded."
            elif status_code == 401:
                error_msg = "PhishTank returned HTTP 401 — invalid API key."
            else:
                error_msg = f"PhishTank returned HTTP {status_code}."
            return ThreatIntelResult(
                source=source,
                found=False,
                lookup_status=LookupStatus.ERROR,
                queried_at=queried_at,
                error=error_msg,
                is_mock=False,
            )
        except Exception:
            logger.exception("Unexpected PhishTank error")
            return ThreatIntelResult(
                source=source,
                found=False,
                lookup_status=LookupStatus.ERROR,
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
        return any(
            r.found and not r.is_mock and r.lookup_status == LookupStatus.MALICIOUS
            for r in results
        )

    @staticmethod
    def get_lookup_statuses(results: List[ThreatIntelResult]) -> List[LookupStatus]:
        """
        Return the lookup_status of all non-mock TI results.
        Used by the risk assessor to determine UNKNOWN state. (F7)
        """
        return [r.lookup_status for r in results if not r.is_mock]

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
        error_count = sum(
            1 for r in results
            if r.lookup_status in (LookupStatus.ERROR, LookupStatus.TIMEOUT)
            and not r.is_mock
        )
        not_configured_count = sum(
            1 for r in results
            if r.lookup_status in (LookupStatus.NOT_CONFIGURED, LookupStatus.DISABLED)
            and not r.is_mock
        )
        clean_count = sum(
            1 for r in results
            if r.lookup_status == LookupStatus.CLEAN and not r.is_mock
        )
        total_queried = len([
            r for r in results
            if r.lookup_status in (LookupStatus.CLEAN, LookupStatus.MALICIOUS)
            and not r.is_mock
        ])

        if found_count > 0:
            if error_count > 0:
                return {
                    "verdict": "MALICIOUS",
                    "confidence": "HIGH",
                    "reasoning": (
                        f"Found in {found_count} feed(s). "
                        f"{error_count} feed(s) unavailable, but confirmed malicious "
                        "evidence takes precedence."
                    ),
                }
            return {
                "verdict": "MALICIOUS",
                "confidence": "HIGH",
                "reasoning": f"Confirmed malicious in {found_count} of {total_queried} queried feeds.",
            }

        if not_configured_count == len(results):
            return {
                "verdict": "INCONCLUSIVE",
                "confidence": "LOW",
                "reasoning": "No threat intelligence feeds are configured. Local analysis only.",
            }

        if error_count + not_configured_count == len(results):
            return {
                "verdict": "INCONCLUSIVE",
                "confidence": "LOW",
                "reasoning": (
                    "All queried threat intelligence feeds were unavailable. "
                    "Local analysis still applies."
                ),
            }

        if error_count > 0 and clean_count > 0:
            return {
                "verdict": "MIXED",
                "confidence": "MEDIUM",
                "reasoning": (
                    f"{clean_count} feed(s) returned clean results, but "
                    f"{error_count} feed(s) were unavailable. Incomplete evidence."
                ),
            }

        return {
            "verdict": "CLEAN",
            "confidence": "MEDIUM",
            "reasoning": (
                f"Not found in any of the {total_queried} queried feeds. "
                "This is not proof of safety."
            ),
        }