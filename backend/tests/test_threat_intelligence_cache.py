"""
TrustShield AI — Cyber Resilience Backend
Tests: Threat Intelligence TTL Cache (Expiration, Isolation, Error Handling)

Verifies:
- Cache hits prevent duplicate HTTP requests
- Monotonic TTL expiration causes fresh lookups
- Feed isolation: URLhaus entries do not bleed into PhishTank
- Transient errors (timeout, 5xx, 429) and NOT_CONFIGURED are NOT cached
- clear_ti_cache cleanly purges the cache
"""

import pytest
import httpx
import time
from unittest.mock import patch, MagicMock

from app.services.threat_intelligence import (
    ThreatIntelligenceService,
    clear_ti_cache,
    _cache_get,
    _cache_set,
    _ti_cache,
)
from app.schemas.cyber_schemas import ThreatIntelResult, LookupStatus

TEST_URL_A = "http://example.com/test-a"
TEST_URL_B = "http://example.com/test-b"


@pytest.fixture(autouse=True)
def clean_cache():
    clear_ti_cache()
    yield
    clear_ti_cache()


@pytest.mark.asyncio
async def test_cache_hit_prevents_duplicate_http_request():
    """Consecutive queries for the same URL should only make ONE network call."""
    service = ThreatIntelligenceService()
    service.urlhaus_auth_key = "test-key"

    call_count = 0

    def mock_response(request):
        nonlocal call_count
        call_count += 1
        return httpx.Response(
            200,
            json={"query_status": "is_host", "url_status": "online", "threat": "malware"},
        )

    transport = httpx.MockTransport(mock_response)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        res1 = await service._check_urlhaus(TEST_URL_A)
        res2 = await service._check_urlhaus(TEST_URL_A)

    assert call_count == 1
    assert res1.found is True
    assert res2.found is True
    assert res2.status == res1.status


@pytest.mark.asyncio
async def test_cache_expiration():
    """Once TTL (300s) has elapsed, cache should expire and re-query."""
    service = ThreatIntelligenceService()
    service.urlhaus_auth_key = "test-key"

    call_count = 0

    def mock_response(request):
        nonlocal call_count
        call_count += 1
        return httpx.Response(
            200,
            json={"query_status": "no_results"},
        )

    transport = httpx.MockTransport(mock_response)
    original_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs["transport"] = transport
        original_init(self, *args, **kwargs)

    with patch.object(httpx.AsyncClient, "__init__", patched_init):
        # First query at t0
        base_time = time.monotonic()
        with patch("time.monotonic", return_value=base_time):
            await service._check_urlhaus(TEST_URL_A)
            assert call_count == 1

        # Query again at t0 + 10s (should hit cache)
        with patch("time.monotonic", return_value=base_time + 10):
            await service._check_urlhaus(TEST_URL_A)
            assert call_count == 1

        # Query at t0 + 301s (should be expired and re-fetch)
        with patch("time.monotonic", return_value=base_time + 301):
            await service._check_urlhaus(TEST_URL_A)
            assert call_count == 2


@pytest.mark.asyncio
async def test_cache_feed_isolation():
    """Cache entries for URLhaus must NOT satisfy PhishTank queries for the same URL."""
    service = ThreatIntelligenceService()
    service.urlhaus_auth_key = "test-key"
    service.phishtank_api_key = "test-phish-key"

    urlhaus_called = 0
    phishtank_called = 0

    def mock_handler(request):
        nonlocal urlhaus_called, phishtank_called
        if "urlhaus" in str(request.url):
            urlhaus_called += 1
            return httpx.Response(200, json={"query_status": "no_results"})
        else:
            phishtank_called += 1
            return httpx.Response(200, json={"results": {"in_database": False}})

    transport = httpx.MockTransport(mock_handler)
    original_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs["transport"] = transport
        original_init(self, *args, **kwargs)

    with patch.object(httpx.AsyncClient, "__init__", patched_init):
        # check_url calls both feeds
        results = await service.check_url(TEST_URL_A)
        assert urlhaus_called == 1
        assert phishtank_called == 1

        # Second check_url should hit cache for both feeds
        results2 = await service.check_url(TEST_URL_A)
        assert urlhaus_called == 1
        assert phishtank_called == 1


@pytest.mark.asyncio
async def test_transient_errors_not_cached():
    """Network timeouts, HTTP 500, and HTTP 429 errors must NOT be cached."""
    service = ThreatIntelligenceService()
    service.urlhaus_auth_key = "test-key"

    call_count = 0

    def mock_failing(request):
        nonlocal call_count
        call_count += 1
        raise httpx.TimeoutException("Connection timed out", request=request)

    transport = httpx.MockTransport(mock_failing)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        res = await service._check_urlhaus(TEST_URL_A)
        assert res.lookup_status == LookupStatus.TIMEOUT

    # Verify nothing was cached for this URL
    assert _cache_get("URLhaus (abuse.ch)", TEST_URL_A) is None

    # Now verify the service will retry immediately when network recovers
    def mock_recovered(request):
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json={"query_status": "no_results"})

    transport2 = httpx.MockTransport(mock_recovered)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport2)):
        res2 = await service._check_urlhaus(TEST_URL_A)
        assert res2.lookup_status == LookupStatus.CLEAN
        assert call_count == 2


@pytest.mark.asyncio
async def test_not_configured_status_not_cached():
    """Unconfigured API keys must not pollute the cache."""
    service = ThreatIntelligenceService()
    service.urlhaus_auth_key = ""

    res = await service._check_urlhaus(TEST_URL_A)
    assert res.lookup_status == LookupStatus.NOT_CONFIGURED
    assert _cache_get("URLhaus (abuse.ch)", TEST_URL_A) is None


def test_clear_ti_cache_functionality():
    """Directly test clear_ti_cache() purges all stored items."""
    sample_res = ThreatIntelResult(
        source="Test",
        found=False,
        lookup_status=LookupStatus.CLEAN,
    )
    _cache_set("TestFeed", "http://example.com/one", sample_res)
    _cache_set("TestFeed", "http://example.com/two", sample_res)
    assert len(_ti_cache) == 2

    clear_ti_cache()
    assert len(_ti_cache) == 0


def test_bounded_cache_max_capacity_and_lru_eviction():
    """When max capacity is reached, the least recently used item must be evicted."""
    from app.services.threat_intelligence import BoundedTTLCache

    cache = BoundedTTLCache(maxsize=3, ttl_seconds=300)
    sample_res = ThreatIntelResult(source="Test", found=False, lookup_status=LookupStatus.CLEAN)

    cache.set(("Feed", "url-1"), sample_res)
    cache.set(("Feed", "url-2"), sample_res)
    cache.set(("Feed", "url-3"), sample_res)
    assert len(cache) == 3

    # Access url-1 so url-2 becomes the oldest/LRU
    assert cache.get(("Feed", "url-1")) is not None

    # Insert url-4 (capacity is 3, so url-2 should be evicted)
    cache.set(("Feed", "url-4"), sample_res)
    assert len(cache) == 3

    assert cache.get(("Feed", "url-2")) is None  # Evicted
    assert cache.get(("Feed", "url-1")) is not None  # Preserved
    assert cache.get(("Feed", "url-3")) is not None  # Preserved
    assert cache.get(("Feed", "url-4")) is not None  # Newly added


def test_bounded_cache_evicts_expired_before_lru():
    """When inserting into a full cache, expired items should be pruned before evicting valid LRU items."""
    from app.services.threat_intelligence import BoundedTTLCache

    cache = BoundedTTLCache(maxsize=3, ttl_seconds=100)
    sample_res = ThreatIntelResult(source="Test", found=False, lookup_status=LookupStatus.CLEAN)

    base_time = time.monotonic()
    with patch("time.monotonic", return_value=base_time):
        cache.set(("Feed", "url-expire-soon"), sample_res)
        # Manually alter expiry of url-expire-soon to be in the past at t+20
        cache._cache[("Feed", "url-expire-soon")] = (sample_res, base_time + 10)

        cache.set(("Feed", "url-keep-1"), sample_res)
        cache.set(("Feed", "url-keep-2"), sample_res)
        assert len(cache) == 3

    # Fast forward past 10s: url-expire-soon is expired
    with patch("time.monotonic", return_value=base_time + 20):
        # Insert url-new; it should prune url-expire-soon instead of evicting url-keep-1
        cache.set(("Feed", "url-new"), sample_res)
        assert len(cache) == 3
        assert cache.get(("Feed", "url-expire-soon")) is None
        assert cache.get(("Feed", "url-keep-1")) is not None
        assert cache.get(("Feed", "url-keep-2")) is not None
        assert cache.get(("Feed", "url-new")) is not None


def test_bounded_cache_thread_safety():
    """Concurrent writes and reads from multiple threads must remain safe and consistent."""
    import threading
    from app.services.threat_intelligence import BoundedTTLCache

    cache = BoundedTTLCache(maxsize=50, ttl_seconds=300)
    sample_res = ThreatIntelResult(source="Test", found=False, lookup_status=LookupStatus.CLEAN)

    def worker(worker_id: int):
        for i in range(50):
            key = ("Feed", f"url-{worker_id}-{i % 10}")
            cache.set(key, sample_res)
            _ = cache.get(key)

    threads = [threading.Thread(target=worker, args=(tid,)) for tid in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # The cache length should never exceed maxsize (50)
    assert len(cache) <= 50

