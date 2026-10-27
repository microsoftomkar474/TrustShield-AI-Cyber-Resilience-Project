import pytest
import httpx
from unittest.mock import patch
from app.services.threat_intelligence import ThreatIntelligenceService

TEST_URL = "http://example.com/login"

@pytest.fixture
def ti_service():
    service = ThreatIntelligenceService()
    # Force a fake PhishTank key so the service actually calls it
    service.phishtank_api_key = "fake-test-key"
    return service

@pytest.mark.asyncio
async def test_phishtank_found(ti_service):
    """Simulates PhishTank returning a confirmed phishing URL."""
    def mock_handler(request):
        if "urlhaus" in str(request.url):
            return httpx.Response(200, json={"query_status": "no_results"})
        return httpx.Response(200, json={"results": {"in_database": True, "valid": True, "verified": True}})

    transport = httpx.MockTransport(mock_handler)
    
    # Patch the __init__ to inject our mock transport into every new client
    original_init = httpx.AsyncClient.__init__
    def patched_init(self, *args, **kwargs):
        kwargs['transport'] = transport
        original_init(self, *args, **kwargs)

    with patch.object(httpx.AsyncClient, '__init__', patched_init):
        results = await ti_service.check_url(TEST_URL)

    phishtank_result = next(r for r in results if r.source == "PhishTank")
    assert phishtank_result.found is True
    
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