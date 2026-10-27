import pytest
import httpx
from datetime import datetime, timezone
from unittest.mock import patch

from app.services.threat_intelligence import ThreatIntelligenceService
from app.schemas.cyber_schemas import ThreatIntelResult
from app.core.config import settings

# A valid test URL
TEST_URL = "http://192.0.2.1/login/verify-account"

@pytest.fixture
def ti_service():
    """Provides a fresh service instance for each test."""
    return ThreatIntelligenceService()

@pytest.mark.asyncio
async def test_urlhaus_found_malicious(ti_service):
    """Simulates URLhaus returning a confirmed malicious URL."""
    
    # Define what the fake URLhaus server returns
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

    # Patch the AsyncClient to use our mock transport
    transport = httpx.MockTransport(mock_response)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        results = await ti_service.check_url(TEST_URL)
        
    urlhaus_result = next(r for r in results if r.source == "URLhaus (abuse.ch)")
    assert urlhaus_result.found is True
    assert "malware_download" in urlhaus_result.status
    assert urlhaus_result.error is None
    assert urlhaus_result.is_mock is False

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

@pytest.mark.asyncio
async def test_urlhaus_missing_key(ti_service):
    """Ensures the service refuses to make a request if Auth-Key is missing."""
    
    # Temporarily clear the key
    original_key = ti_service.urlhaus_auth_key
    ti_service.urlhaus_auth_key = ""
    
    try:
        results = await ti_service.check_url(TEST_URL)
        urlhaus_result = next(r for r in results if r.source == "URLhaus (abuse.ch)")
        assert urlhaus_result.found is False
        assert "Auth-Key not configured" in urlhaus_result.status
        assert "missing" in urlhaus_result.error
    finally:
        ti_service.urlhaus_auth_key = original_key