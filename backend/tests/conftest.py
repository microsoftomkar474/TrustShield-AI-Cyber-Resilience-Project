"""
TrustShield AI — Cyber Resilience Backend
pytest configuration

Sets asyncio mode to 'auto' so async test functions
are automatically recognized and run.
"""
import pytest


# Tell pytest-asyncio to automatically handle async test functions
# without requiring @pytest.mark.asyncio on every test
def pytest_configure(config):
    config.addinivalue_line(
        "markers", "asyncio: mark test as async"
    )
