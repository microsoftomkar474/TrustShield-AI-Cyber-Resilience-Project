"""
TrustShield AI — Cyber Resilience Backend
Tests: Threat Intelligence Service (PhishTank + multi-feed correlation)

Tests mock all HTTP responses — no real API calls are made.
"""
import pytest
import httpx
from unittest.mock import patch
from app.services.threat_intelligence import ThreatIntelligenceService, clear_ti_cache
from app.schemas.cyber_schemas import LookupStatus

TEST_URL = "http://example.com/login"


@pytest.fixture(autouse=True)
def reset_ti_cache():
    """Clear the TI cache before every test to prevent cross-test contamination."""
    clear_ti_cache()
    yield
    clear_ti_cache()


@pytest.fixture
def ti_service():
    service = ThreatIntelligenceService()
    # Force fake keys so the service actually exercises both feeds
    service.phishtank_api_key = "fake-test-key"
    if not service.urlhaus_auth_key:
        service.urlhaus_auth_key = "test-auth-key"
    return service


@pytest.mark.asyncio
async def test_phishtank_found(ti_service):
    """Simulates PhishTank returning a confirmed phishing URL."""
    def mock_handler(request):
        if "urlhaus" in str(request.url):
            return httpx.Response(200, json={"query_status": "no_results"})
        return httpx.Response(200, json={"results": {"in_database": True, "valid": True, "verified": True}})

    transport = httpx.MockTransport(mock_handler)

    original_init = httpx.AsyncClient.__init__
    def patched_init(self, *args, **kwargs):
        kwargs['transport'] = transport
        original_init(self, *args, **kwargs)

    with patch.object(httpx.AsyncClient, '__init__', patched_init):
        results = await ti_service.check_url(TEST_URL)

    phishtank_result = next(r for r in results if r.source == "PhishTank")
    assert phishtank_result.found is True
    assert phishtank_result.lookup_status == LookupStatus.MALICIOUS

    correlation = ThreatIntelligenceService.correlate_verdict(results)
    assert correlation["verdict"] == "MALICIOUS"
    assert correlation["confidence"] == "HIGH"


@pytest.mark.asyncio
async def test_phishtank_not_found(ti_service):
    """Simulates both feeds returning clean results."""
    def mock_handler(request):
        if "urlhaus" in str(request.url):
            return httpx.Response(200, json={"query_status": "no_results"})
        return httpx.Response(200, json={"results": {"in_database": False}})

    transport = httpx.MockTransport(mock_handler)

    original_init = httpx.AsyncClient.__init__
    def patched_init(self, *args, **kwargs):
        kwargs['transport'] = transport
        original_init(self, *args, **kwargs)

    with patch.object(httpx.AsyncClient, '__init__', patched_init):
        results = await ti_service.check_url(TEST_URL)

    correlation = ThreatIntelligenceService.correlate_verdict(results)
    assert correlation["verdict"] == "CLEAN"
    assert correlation["confidence"] == "MEDIUM"


@pytest.mark.asyncio
async def test_correlation_mixed(ti_service):
    """Simulates URLhaus failing but PhishTank returning clean."""
    def mock_handler(request):
        if "urlhaus" in str(request.url):
            return httpx.Response(500, json={"error": "server down"})
        return httpx.Response(200, json={"results": {"in_database": False}})

    transport = httpx.MockTransport(mock_handler)

    original_init = httpx.AsyncClient.__init__
    def patched_init(self, *args, **kwargs):
        kwargs['transport'] = transport
        original_init(self, *args, **kwargs)

    with patch.object(httpx.AsyncClient, '__init__', patched_init):
        results = await ti_service.check_url(TEST_URL)

    correlation = ThreatIntelligenceService.correlate_verdict(results)
    assert correlation["verdict"] == "MIXED"
    assert correlation["confidence"] == "MEDIUM"


@pytest.mark.asyncio
async def test_get_lookup_statuses(ti_service):
    """Verifies get_lookup_statuses returns correct statuses from results."""
    def mock_handler(request):
        if "urlhaus" in str(request.url):
            return httpx.Response(200, json={"query_status": "no_results"})
        return httpx.Response(200, json={"results": {"in_database": False}})

    transport = httpx.MockTransport(mock_handler)

    original_init = httpx.AsyncClient.__init__
    def patched_init(self, *args, **kwargs):
        kwargs['transport'] = transport
        original_init(self, *args, **kwargs)

    with patch.object(httpx.AsyncClient, '__init__', patched_init):
        results = await ti_service.check_url(TEST_URL)

    statuses = ThreatIntelligenceService.get_lookup_statuses(results)
    assert all(s in list(LookupStatus) for s in statuses)
    # Both feeds should return CLEAN for no_results/not_in_database
    clean_statuses = [s for s in statuses if s == LookupStatus.CLEAN]
    assert len(clean_statuses) == 2