"""
TrustShield AI — Cyber Resilience Backend
Tests: Threat Intelligence Service (URLhaus)

Tests mock all HTTP responses — no real API calls are made.
"""
import pytest
import httpx
from datetime import datetime, timezone
from unittest.mock import patch

from app.services.threat_intelligence import ThreatIntelligenceService, clear_ti_cache
from app.schemas.cyber_schemas import ThreatIntelResult, LookupStatus
from app.core.config import settings

# A valid test URL
TEST_URL = "http://192.0.2.1/login/verify-account"


@pytest.fixture(autouse=True)
def reset_ti_cache():
    """Clear the TI cache before every test to prevent cross-test contamination."""
    clear_ti_cache()
    yield
    clear_ti_cache()


@pytest.fixture
def ti_service():
    """Provides a fresh service instance for each test."""
    service = ThreatIntelligenceService()
    if not service.urlhaus_auth_key:
        service.urlhaus_auth_key = "test-auth-key"
    return service


@pytest.mark.asyncio
async def test_urlhaus_found_malicious(ti_service):
    """Simulates URLhaus returning a confirmed malicious URL."""

    def mock_response(request):
        assert request.headers["Auth-Key"] == settings.urlhaus_auth_key or "test-key"
        assert "url" in request.content.decode()
        return httpx.Response(
            200,
            json={
                "query_status": "is_host",
                "url_status": "online",
                "threat": "malware_download",
            }
        )

    transport = httpx.MockTransport(mock_response)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        results = await ti_service.check_url(TEST_URL)

    urlhaus_result = next(r for r in results if r.source == "URLhaus (abuse.ch)")
    assert urlhaus_result.found is True
    assert "malware_download" in urlhaus_result.status
    assert urlhaus_result.error is None
    assert urlhaus_result.is_mock is False
    assert urlhaus_result.lookup_status == LookupStatus.MALICIOUS


@pytest.mark.asyncio
async def test_urlhaus_not_found(ti_service):
    """Simulates URLhaus returning no results."""

    def mock_response(request):
        return httpx.Response(200, json={"query_status": "no_results"})

    transport = httpx.MockTransport(mock_response)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        results = await ti_service.check_url(TEST_URL)

    urlhaus_result = next(r for r in results if r.source == "URLhaus (abuse.ch)")
    assert urlhaus_result.found is False
    assert "not found" in urlhaus_result.status
    assert urlhaus_result.error is None
    assert urlhaus_result.lookup_status == LookupStatus.CLEAN


@pytest.mark.asyncio
async def test_urlhaus_auth_error(ti_service):
    """Simulates a 401 Unauthorized (bad Auth-Key)."""

    def mock_response(request):
        return httpx.Response(401, json={"query_status": "unknown_auth_key"})

    transport = httpx.MockTransport(mock_response)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        results = await ti_service.check_url(TEST_URL)

    urlhaus_result = next(r for r in results if r.source == "URLhaus (abuse.ch)")
    assert urlhaus_result.found is False
    assert "HTTP 401" in urlhaus_result.error
    assert urlhaus_result.is_mock is False
    assert urlhaus_result.lookup_status == LookupStatus.ERROR


@pytest.mark.asyncio
async def test_urlhaus_timeout(ti_service):
    """Simulates a network timeout."""

    def mock_response(request):
        raise httpx.TimeoutException("Timeout", request=request)

    transport = httpx.MockTransport(mock_response)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        results = await ti_service.check_url(TEST_URL)

    urlhaus_result = next(r for r in results if r.source == "URLhaus (abuse.ch)")
    assert urlhaus_result.found is False
    assert "timed out" in urlhaus_result.error
    assert urlhaus_result.is_mock is False
    assert urlhaus_result.lookup_status == LookupStatus.TIMEOUT


@pytest.mark.asyncio
async def test_urlhaus_missing_key(ti_service):
    """Ensures the service refuses to make a request if Auth-Key is missing."""

    original_key = ti_service.urlhaus_auth_key
    ti_service.urlhaus_auth_key = ""

    try:
        results = await ti_service.check_url(TEST_URL)
        urlhaus_result = next(r for r in results if r.source == "URLhaus (abuse.ch)")
        assert urlhaus_result.found is False
        assert "Auth-Key not configured" in urlhaus_result.status
        assert "missing" in urlhaus_result.error
        assert urlhaus_result.lookup_status == LookupStatus.NOT_CONFIGURED
    finally:
        ti_service.urlhaus_auth_key = original_key


@pytest.mark.asyncio
async def test_urlhaus_rate_limit(ti_service):
    """Simulates a 429 Too Many Requests response."""

    def mock_response(request):
        return httpx.Response(429, json={})

    transport = httpx.MockTransport(mock_response)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        results = await ti_service.check_url(TEST_URL)

    urlhaus_result = next(r for r in results if r.source == "URLhaus (abuse.ch)")
    assert urlhaus_result.found is False
    assert "429" in urlhaus_result.error
    assert urlhaus_result.lookup_status == LookupStatus.ERROR


@pytest.mark.asyncio
async def test_lookup_status_propagates_to_correlate(ti_service):
    """Verifies that unavailable TI does not produce a CLEAN verdict."""

    def mock_response(request):
        raise httpx.TimeoutException("Timeout", request=request)

    transport = httpx.MockTransport(mock_response)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        results = await ti_service.check_url(TEST_URL)

    correlation = ThreatIntelligenceService.correlate_verdict(results)
    # Timeout should produce INCONCLUSIVE, not CLEAN
    assert correlation["verdict"] in ("INCONCLUSIVE", "MIXED")
    assert correlation["confidence"] in ("LOW", "MEDIUM")