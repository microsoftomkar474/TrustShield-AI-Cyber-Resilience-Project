import pytest
from app.services.url_analyzer import URLAnalyzer

analyzer = URLAnalyzer()

def get_codes(url: str) -> set:
    indicators, _ = analyzer.analyse(url)
    return {ind.code for ind in indicators}

class TestAdvancedURLAttacks:
    
    def test_punycode_homograph_attack(self):
        """Attackers use Cyrillic characters that look like English to bypass filters."""
        # This is the Cyrillic 'а' (U+0430), not the English 'a'
        homograph_url = "https://pаypal.com/login" 
        # Your current code does not normalize to punycode (xn--), 
        # so it might miss this entirely.
        indicators, components = analyzer.analyse(homograph_url)
        # We expect the system to flag this somehow, or at least not crash.
        assert components["hostname"] is not None
        
    def test_invalid_ipv6_crash(self):
        """Malformed IPv6 brackets can cause urlparse to crash when accessing .port."""
        malformed_ipv6 = "http://[::1]:8080/login"
        # This should NOT raise a ValueError.
        try:
            indicators, components = analyzer.analyse(malformed_ipv6)
            assert isinstance(indicators, list)
        except ValueError as e:
            pytest.fail(f"Analyzer crashed on malformed IPv6: {e}")

    def test_scheme_relative_url(self):
        """URLs starting with // are scheme-relative and should be flagged."""
        url = "//evil.com/login"
        codes = get_codes(url)
        # Does it catch this as having no scheme?
        assert "URL_NO_SCHEME" in codes

    def test_null_byte_injection(self):
        """Attackers sometimes inject %00 to bypass string checks."""
        url = "https://example.com/login%00.jpg"
        codes = get_codes(url)
        # This should not crash, and should probably flag the encoding.
        assert isinstance(codes, set)